from app.oai_models import (ChatCompletionRequest,
                            ChatCompletionStreamResponse,
                            ChatCompletionAdditionalParameters,
                            ErrorResponse,
                            random_uuid,
                            ChatCompletionMessageParam)
from typing import AsyncGenerator, Optional, Any, Callable, Union
import asyncio
from app.oai_streaming import create_streaming_response, ChatCompletionResponseBuilder
from app.utils import AgentResourceManager, convert_mcp_tools_to_openai_format, get_user_messages
import logging
from app.configs import settings
from app.utils import refine_chat_history, wrap_chunk, refine_assistant_message, refine_mcp_response, execute_openai_compatible_toolcall
import os
import json
from mcp.types import TextContent, EmbeddedResource
import re
from src.agent_sentinel.utils import detect_project_languages


logger = logging.getLogger(__name__)

async def wrapstream(
    streaming_iter: AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None], 
    callback: Callable[[ChatCompletionStreamResponse | ErrorResponse], None]
):
    async for chunk in streaming_iter:
        callback(chunk)

        if chunk.choices[0].delta.content:
            yield chunk

async def get_system_prompt(messages: list[ChatCompletionMessageParam] | list[dict[str, Any]]) -> str:
    last_3_messages = get_user_messages(messages, 3)

    base = ''

    if os.path.exists("system_prompt.txt"):
        with open("system_prompt.txt", "r") as f:
            base = f.read()

    github_repo_pattern = re.compile(r'https://github\.com/[^/]+/[^/]+')
    user_message = '\n'.join(last_3_messages)

    found_repo = github_repo_pattern.findall(user_message)
    repo_info_str = ''

    if len(found_repo) > 0:
        repo_info_str = f"Preliminary information about user mentioned repositories:\n"
        
    attach_repo_info = False

    for i, match in enumerate(found_repo):
        try:
            path = clone_repo(match)

            if not path or not os.path.exists(path):
                repo_info_str += f"Repo {match} is invalid or not accessible\n"
                attach_repo_info = True
                continue

            _repo: RepoInfo = RepoInfo(path)

            repo_info_str += f"Repo: {_repo.repo_url}\n"
            repo_info_str += f"Default Branch: {_repo.branch}\n"
            repo_info_str += f"Languages: {detect_project_languages(path)}\n"
            repo_info_str += f"Project structure: {get_directory_tree(path, max_items=5)}\n\n"
    
            attach_repo_info = True
        except Exception as e:
            logger.error(f"Error cloning repository {match}: {e}", exc_info=True)

    if attach_repo_info:
        base += f"\n{repo_info_str}"

    return base

from src.agent_sentinel import mcp as git_action_mcp, audit_mcp as source_code_mcp, main as security_scanners
from src.agent_sentinel.utils import merge_reports, Report, ErrorReport, SeverityLevel
from src.agent_sentinel.git_utils import RepoInfo, clone_repo, get_directory_tree 

class StopAgentLoop(Exception): pass

async def list_toolcalls() -> list[dict[str, Any]]: 
    res = [
        *(await git_action_mcp._mcp_list_tools()),
        *(await source_code_mcp._mcp_list_tools())
    ]
    
    return convert_mcp_tools_to_openai_format(res)

fn_mapping = {
    'security_scan': security_scanners.security_scan.fn
}

def fmt_report(report: Report, repo: RepoInfo | None = None) -> str:
    if repo and report.line_start and report.line_end:
        return f"[{report.file_path}:({report.line_start}:{report.line_end})]({repo.get_reference(report.file_path, report.line_start, report.line_end)}) - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"
    else:
        return f"{report.file_path}:{report.line_number} - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"

from src.agent_sentinel.cwe_utils import CWEWeakness, get_cwe_by_id

VALIDATION_SYSTEM_PROMPT = """
Your task is to confirm a security finding is valid or not, in one step. In case the severity level is not appropriate, change it and explain why.

Found:
{found}

Context:
{context}

References:
{references}

By default, if no action is taken, the security issue finding is valid. In case the secret value found is just dummy, reject it. 
"""

VALIDATION_ACTION = [
    { 
        "type": "function",
        "function": {
            "name": "reject",
            "description": "Reject the security issue finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "The reason for rejecting the security issue finding"
                    }
                }
            }
        },
        "type": "function",
        "function": {
            "name": "change_severity_level",
            "description": "Change the severity level of the security issue finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "The severity level of the security issue finding if the current severity level is not appropriate",
                        "enum": [
                            "LOW",
                            "MEDIUM",
                            "HIGH",
                            "CRITICAL"
                        ]
                    },
                    "reason": {
                        "type": "string",
                        "description": "The reason for changing the severity level of the security issue finding"
                    }
                }
            }
        }
    }
]

import openai

def change_severity_level(report: Report, severity: str) -> Report:
    severity = severity.upper()

    if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        logger.warning(f"Invalid severity level: {severity}")
        return report

    report.severity = SeverityLevel(severity)
    return report

def is_match(report_1: Report, report_2: Report) -> bool:
    if report_1.file_path != report_2.file_path:
        return False

    if report_1.line_start != report_2.line_start:
        return False

    if report_1.line_end != report_2.line_end:
        return False
    
    if report_1.cwe != report_2.cwe:
        return False

    return True

import base64

def construct_file_response(file_paths: list[str]) -> str:
    files_xml = ""
    for file_path in file_paths:
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            encoded_data = base64.b64encode(file_bytes).decode("utf-8")
            filename = os.path.basename(file_path)
            files_xml += (
                f"  <file>\n"
                f"    <filename>{filename}</filename>\n"
                f"    <filedata>{encoded_data}</filedata>\n"
                f"  </file>\n"
            )
        except Exception as e:
            continue

    return f"<files>{files_xml}</files>"

async def confirm_report(report: Report, confirmed_reports: list[Report], deep_mode: bool, repo: RepoInfo | None = None) -> Report | None:
    if any(is_match(report, confirmed_report) for confirmed_report in confirmed_reports):
        logger.info(f"Report is already confirmed: {report}")
        return None

    if report.language == 'dependency':
        logger.info(f"Dependency report is no need to be confirmed again")
        return report 

    context = repo.reveal_content(
        report.file_path, 
        report.line_start, 
        report.line_end, 
        A=2, B=2
    )

    if not context:
        logger.warning(f"Failed to reveal content for {report.file_path}:{report.line_start}:{report.line_end} (file not found or invalid line number)")
        return None
    
    if not deep_mode and report.language != 'code':
        logger.info(f"Dependency report is no need to be confirmed in deep mode")
        return report

    cwe_ids = [
        _id.strip() 
        for _id in report.cwe.split(',')
    ]

    cwes = [
        get_cwe_by_id(cwe_id) 
        for cwe_id in cwe_ids
    ]
    
    cwes = [
        cwe 
        for cwe in cwes 
        if cwe is not None
    ]

    references = ''

    if not cwes:
        references = "No CWE found for this security issue finding"
    
    for i, cwe in enumerate(cwes):
        references += f"{i + 1}. CWE-{cwe.id} - {cwe.name}\n"
        references += f"Description: {cwe.description}\n"
        references += f"Extended Description: {cwe.extended_description}\n"

        if len(cwe.examples) > 0:
            references += f"Examples: \n"

            for example in cwe.examples:
                references += f"```\n{example}\n```\n"

        if len(cwe.consequences) > 0:
            references += f"Consequences: \n"

            for j, consequence in enumerate(cwe.consequences):
                references += f"{j + 1}. {consequence}\n"

        references += "\n"

    client = openai.AsyncClient(
        base_url=settings.llm_base_url, 
        api_key=settings.llm_api_key
    )

    messages = [
        {
            "role": "system",
            "content": VALIDATION_SYSTEM_PROMPT.format(
                found=fmt_report(report, repo),
                context=context,
                references=references
            )
        }
    ]
    
    completion = await client.chat.completions.create(
        model=settings.llm_model_id,
        messages=messages,
        tools=VALIDATION_ACTION,
        tool_choice="auto"
    )

    tools = completion.choices[0].message.tool_calls

    for tool in tools:
        args_json = json.loads(tool.function.arguments)

        if tool.function.name == 'reject':
            logger.warning(f"Rejected security issue finding: {args_json.get('reason', 'Unknown reason')}")
            return None

        elif tool.function.name == 'change_severity_level':
            logger.info(f"Changing severity level of security issue finding: {args_json.get('reason', 'Unknown reason')}")
            report = change_severity_level(report, args_json.get('severity'))
            break

    return report

async def generate_security_report(confirmed_reports: list[Report], event: asyncio.Event) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    # TODO: write this
    yield wrap_chunk(random_uuid(), merge_reports(confirmed_reports), "assistant")

async def handoff(tool_name: str, tool_args: dict[str, Any], event: asyncio.Event) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    
    if tool_name not in fn_mapping:
        yield wrap_chunk(random_uuid(), f"{tool_name} not found", "assistant")
        return

    fn = fn_mapping[tool_name]
    confirmed_reports = []
    deep_mode = tool_args.get('deep', True)
    repo_url = tool_args.get('repo_url', None)

    repo = None

    if repo_url is not None: 
        repo = RepoInfo(clone_repo(repo_url, tool_args.get('branch', None)))

    if not repo:
        yield wrap_chunk(random_uuid(), f"Repository is invalid or not accessible. No security scan is performed.", "assistant")
        return

    async for report in fn(**tool_args):
        if event.is_set():
            logger.info(f"[toolcall] Event signal received, stopping...")
            return

        report: Report | ErrorReport

        if isinstance(report, ErrorReport):
            logger.warning(f"Error report: {report}")

        else:
            report = await confirm_report(report, confirmed_reports, deep_mode, repo)

            if report is None:
                logger.warning(f"Report is rejected...")
                continue

            confirmed_reports.append(report)

            yield wrap_chunk(
                random_uuid(), 
                f"\n<details>\n<summary>{report.tool} found an issue - {report.severity} - {report.cwe or 'Unknown CWE'}</summary>\n```plain\n{fmt_report(report, repo)}\n```\n</details>\n", 
                "assistant"
            )

            await asyncio.sleep(0.3) # to avoid broken pipe

    if not confirmed_reports:
        yield wrap_chunk(random_uuid(), f"Repository is well-secured, no issues found!", "assistant")
        return

    async for chunk in generate_security_report(confirmed_reports, event):
        yield chunk

    raise StopAgentLoop()

async def execute_toolcall_request(
    tool_name: str, 
    tool_args: dict[str, Any],
    event: asyncio.Event
) -> list[Union[TextContent, EmbeddedResource]] | AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    for tool in await source_code_mcp._mcp_list_tools():
        if tool.name == tool_name:
            return handoff(tool_name, tool_args, event) # async generator, no need to await

    return await execute_openai_compatible_toolcall(tool_name, tool_args, git_action_mcp)

async def handle_request(
    request: ChatCompletionRequest, 
    event: asyncio.Event,
    additional_parameters: Optional[ChatCompletionAdditionalParameters] = None
) -> AsyncGenerator[ChatCompletionStreamResponse, None]:
    messages = request.messages
    assert len(request.messages) > 0, "No messages in the request"

    arm = AgentResourceManager()

    system_prompt = await get_system_prompt(messages)
    logger.info(f"[main] System prompt: {system_prompt}")
    
    messages: list[dict[str, Any]] = refine_chat_history(messages, system_prompt, arm)

    oai_tools = await list_toolcalls()
    
    finished = False
    n_calls, max_calls = 0, 25

    while not finished and not event.is_set():
        completion_builder = ChatCompletionResponseBuilder()
        requires_toolcall = n_calls < max_calls
        toolcalls = oai_tools

        payload = dict(
            messages=messages,
            tools=toolcalls,
            tool_choice="auto",
            model=settings.llm_model_id
        )

        if not requires_toolcall:
            payload.pop("tools")
            payload.pop("tool_choice")

        streaming_iter = create_streaming_response(
            settings.llm_base_url,
            settings.llm_api_key,
            **payload
        )

        # need to reveal resource
        async for chunk in arm.handle_streaming_response(wrapstream(streaming_iter, completion_builder.add_chunk)):
            if event.is_set():
                logger.info(f"[main] Event signal received, stopping the request")
                break

            yield chunk

        completion = await completion_builder.build()
        messages.append(refine_assistant_message(completion.choices[0].message))
        
        toolcalls_requested = (completion.choices[0].message.tool_calls or [])

        for call_idx, call in enumerate(toolcalls_requested):
            if event.is_set():
                logger.info(f"[toolcall] Event signal received, stopping the request")
                break

            n_calls += 1

            _id, _name, _args = call.id, call.function.name, call.function.arguments
            _args: dict = json.loads(_args)
            _result = ""

            yield wrap_chunk(random_uuid(), f"<action>Running {_name}...</action>", "assistant")
            result = await execute_toolcall_request(_name, _args, event)
            
            if isinstance(result, AsyncGenerator):
                try:
                    async for chunk in result:
                        if isinstance(chunk, ErrorResponse):
                            raise Exception(chunk.message)

                        chunk_content = chunk.choices[0].delta.content or ""
                        yield chunk

                        _result += chunk_content
                except Exception as e:
                    logger.error(f"Error executing toolcall: {e}", exc_info=True)
                    _result = f"Error executing toolcall: {e}"
                    
                except StopAgentLoop:
                    logger.info(f"[toolcall] StopAgentLoop received, stopping the request")
                    break

                _result = refine_mcp_response(_result, arm)
            else:
                _result = refine_mcp_response(result, arm)
                yield wrap_chunk(random_uuid(), f'<details><summary>Tool call result</summary>\n```json\n{_result}\n```\n</details>\n', "assistant")

            if not isinstance(_result, str):
                try:
                    _result = json.dumps(_result)
                except:
                    _result = str(_result)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": _id,
                    "content": _result
                }
            )

        finished = len(toolcalls_requested) == 0

    os.makedirs("logs", exist_ok=True)
    with open(f"logs/messages-{request.request_id}.json", "w") as f:
        json.dump(messages, f, indent=2)

    yield completion