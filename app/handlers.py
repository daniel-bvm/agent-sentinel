from app.oai_models import (ChatCompletionRequest,
                            ChatCompletionStreamResponse,
                            ChatCompletionAdditionalParameters,
                            ErrorResponse,
                            random_uuid,
                            ChatCompletionMessageParam, OpenAIBaseModel)
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
from collections import Counter

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

            _repo: RepoInfo = RepoInfo(path, "")

            repo_info_str += f"Repo: {_repo.repo_url}\n"
            repo_info_str += f"Default Branch: {_repo.branch}\n"
            repo_info_str += f"Languages: {detect_project_languages(path)}\n"
            repo_info_str += f"Project structure: {get_directory_tree(path, max_items=5)}\n\n"

            attach_repo_info = True
        except Exception as e:
            logger.error(f"Error cloning repository {match}: {e}", exc_info=True)

    if attach_repo_info:
        base += f"\n{repo_info_str}"

    logger.info(f"System prompt: {base}")

    return base

from src.agent_sentinel import mcp as git_action_mcp, audit_mcp as source_code_mcp, diff_mcp as diff_analysis_mcp, main as security_scanners
from src.agent_sentinel.utils import merge_reports, Report, ErrorReport, SeverityLevel
from src.agent_sentinel.git_utils import RepoInfo, clone_repo, get_directory_tree
from src.agent_sentinel.cwe_utils import get_cwe_by_id, CWEWeakness
import openai

class FullyHandoff(OpenAIBaseModel): pass

async def list_toolcalls() -> list[dict[str, Any]]:
    res = [
        *(await git_action_mcp._mcp_list_tools()),
        *(await source_code_mcp._mcp_list_tools()),
        *(await diff_analysis_mcp._mcp_list_tools())
    ]

    return convert_mcp_tools_to_openai_format(res)

fn_mapping = {
    'security_scan': security_scanners.security_scan.fn
}

def fmt_report(report: Report, repo: RepoInfo | None = None) -> str:
    if repo and report.line_start and report.line_end:
        line_info = f":{report.line_start}" if report.line_start == report.line_end else f":{report.line_start}-{report.line_end}"
        return f"[{report.file_path}{line_info}]({repo.get_reference(report.file_path, report.line_start, report.line_end)}) - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"
    else:
        return f"{report.file_path} - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"

def normalize_cwe(cwe: str) -> str:
    return cwe.split(':')[0].strip().upper()

VALIDATION_SYSTEM_PROMPT = """
Your task is to confirm whether a security finding is valid or not, in one step via tool calls. In case the severity level or description is not appropriate, change it and explain why. All information, including issue description and CWE ID are reliable; just make up the description to be prettier if needed, the current categorized CWE is set as intended.

Found:
{found}

Context:
{context}

References:
{references}

By default, if no action is taken, the security issue finding is valid and need attention. In case the secret value found is just dummy or the current implement fully safe to keep, set the severity to SAFE.
"""

VALIDATION_ACTION = [
    {
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
                            "CRITICAL",
                            "SAFE"
                        ]
                    },
                    "reason": {
                        "type": "string",
                        "description": "The reason for changing the severity level of the security issue finding"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "change_information",
            "description": "Change the information of the security issue finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "The reason for changing the description of the security issue finding"
                    },
                    "description": {
                        "type": "string",
                        "description": "The description of the security issue finding if the current description is not appropriate",
                    },
                    "cwe": {
                        "type": "string",
                        "description": "The CWE ID of the security issue finding if the current CWE ID is not appropriate. If there are multiple CWE IDs, separate them with commas.",
                    },
                },
                "required": ["reason"]
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

def change_information(report: Report, description: str, cwe: str) -> Report:
    report.description = description if description else report.description
    report.cwe = cwe if cwe else report.cwe
    return report


def is_match(report_1: Report, report_2: Report) -> bool:
    return (
        report_1.file_path == report_2.file_path and
        report_1.language == report_2.language and
        report_1.processed_information == report_2.processed_information and
        report_1.cwe == report_2.cwe and
        report_1.line_start == report_2.line_start and
        report_1.line_end == report_2.line_end
    )

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

    if report.report_type == 'dependency':
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
        tool_choice="auto",
        temperature=0.1
    )

    for tool in (completion.choices[0].message.tool_calls or []):
        args_json = json.loads(tool.function.arguments)

        if tool.function.name == 'reject':
            logger.warning(f"Rejected security issue finding: {args_json.get('reason', 'Unknown reason')}; {report}")
            return None

        elif tool.function.name == 'change_severity_level':
            from_severity = report.severity.value
            to_severity = args_json.get('severity')

            if to_severity.upper() == 'SAFE':
                logger.info(f"Rejecting security issue finding: {args_json.get('reason', 'Unknown reason')}")
                return None

            if from_severity != to_severity:
                logger.info(f"Changing severity level of security issue finding from {from_severity} to {to_severity}: {args_json.get('reason', 'Unknown reason')}")
                report = change_severity_level(report, args_json.get('severity'))

        elif tool.function.name == 'change_information':
            logger.info(f"Changing information of security issue finding: {args_json.get('description', 'Unknown description')} (Reason: {args_json.get('reason', 'Unknown reason')})")
            report = change_information(report, args_json.get('description'), args_json.get('cwe'))

    return report

from pandas import DataFrame
import pandas as pd

REPORT_WRITTING_TOOLS = [
    # {
    #     "type": "function",
    #     "function": {
    #         "name": "include_table",
    #         "description": "Respond a table in markdown format to the user. Return a label to reference to.",
    #         "parameters": {
    #             "type": "object",
    #             "properties": {
    #                 "df_id": {
    #                     "type": "string",
    #                     "description": "The id of the dataframe to include in the report",
    #                     "enum": [
    #                         "high_severity_df",
    #                         "medium_severity_df",
    #                         "other_df"
    #                     ]
    #                 },
    #                 "columns": {
    #                     "type": "array",
    #                     "description": "Columns in the dataframe to include in the report",
    #                     "items": {
    #                         "type": "string"
    #                     }
    #                 }
    #             },
    #             "required": ["df_id", "columns"]
    #         }
    #     }
    # },
    {
        "type": "function",
        "function": {
            "name": "include_chart",
            "description": "Respond a chart in markdown format to the user. Return a label to reference to.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chart_type": {
                        "type": "string",
                        "description": "The type of the chart to include in the report",
                        "enum": [
                            "bar",
                            "line",
                            "pie"
                        ]
                    },
                    "x_axis": {
                        "type": "string",
                        "description": "The column to use as the x-axis of the chart"
                    },
                    "y_axis": {
                        "type": "string",
                        "description": "The column to use as the y-axis of the chart"
                    }
                },
                "required": ["df_id", "chart_type", "x_axis", "y_axis"]
            }
        }
    }
]

def generate_table_markdown(df: DataFrame, columns: list[str]) -> str:
    if not columns:
        return df.to_markdown(index=False)

    return df[columns].to_markdown(index=False)

def generate_chart_markdown(df: DataFrame, chart_type: str, x_axis: str, y_axis: str) -> str:
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        import io
        import base64

        # Set style
        plt.style.use('default')
        sns.set_palette("husl")

        fig, ax = plt.subplots(figsize=(10, 6))

        if chart_type == "bar":
            if x_axis in df.columns and y_axis in df.columns:
                df.plot(kind='bar', x=x_axis, y=y_axis, ax=ax)
            else:
                # Handle case where columns might not exist
                value_counts = df[x_axis].value_counts() if x_axis in df.columns else df.iloc[:, 0].value_counts()
                value_counts.plot(kind='bar', ax=ax)
                ax.set_ylabel('Count')
        elif chart_type == "pie":
            if x_axis in df.columns:
                df[x_axis].value_counts().plot(kind='pie', ax=ax, autopct='%1.1f%%')
            else:
                df.iloc[:, 0].value_counts().plot(kind='pie', ax=ax, autopct='%1.1f%%')
        elif chart_type == "line":
            if x_axis in df.columns and y_axis in df.columns:
                df.plot(kind='line', x=x_axis, y=y_axis, ax=ax)
            else:
                df.plot(kind='line', ax=ax)

        plt.tight_layout()
        buffer = io.BytesIO()
        plt.savefig(buffer, format='jpeg', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return f"<img src='data:image/jpeg;base64,{image_base64}'/>"

    except Exception as e:
        logger.error(f"Error generating chart: {e}", exc_info=True)
        return f"Error generating chart: {str(e)}"

async def generate_headline(df: DataFrame, repo: RepoInfo | None, arm: AgentResourceManager, event: asyncio.Event) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate executive summary and overview of the security scan results."""

    total_issues = len(df)
    severity_stats = df['severity'].value_counts().to_dict()
    tool_stats = df['tool'].value_counts().to_dict()
    language_stats = df['language'].value_counts().to_dict()

    cwe_counter = Counter()
    for cwe_list in df['cwe'].dropna():
        for cwe in map(str.strip, str(cwe_list).split(',')):
            if cwe:
                cwe_counter[cwe] += 1

    cwe_stats = dict(cwe_counter)
    top5_cwes = sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True)[:5]

    cwe_objs = [
        get_cwe_by_id(cwe_id)
        for cwe_id, _ in top5_cwes
    ]

    # Create context for LLM
    context = {
        "total_issues": total_issues,
        "severity_breakdown": severity_stats,
        "tools_used": list(tool_stats.keys()),
        "languages_scanned": list(language_stats.keys()),
        "top_cwes": [
            f"CWE-{cwe.id}: {cwe.name} ({cwe.description})"
            for cwe in cwe_objs
            if cwe is not None
        ],
        "repo_url": repo.repo_url if repo else "Unknown",
        "data_preview": df.head(5).to_json(orient="records")
    }

    system_prompt = f"""You are a cybersecurity expert creating an executive summary for a security scan report.

Scan Results Context:
- Total Issues Found: {context['total_issues']}
- Severity Distribution: {context['severity_breakdown']}
- Tools Used: {', '.join(context['tools_used'])}
- Languages Scanned: {', '.join(context['languages_scanned'])}
- Top CWEs: {', '.join(context['top_cwes'])}
- Repository: {context['repo_url']}

Create a professional executive summary that:
1. Starts with a clear headline and security status
2. Provides key findings and risk assessment
3. Highlights the most critical issues that need immediate attention
4. Is concise but informative (2-3 paragraphs)
5. Uses appropriate security terminology

Guidelines:
1. Use the data preview to understand the context of the security issues
2. Use the severity distribution to understand the risk of the security issues
3. Keep your response practical, actionable, and focused on helping development teams efficiently address these issues. Use markdown format, bullet points to clarify and bold the headinngs.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Generate the executive summary for this security scan report."}
    ]

    builder = ChatCompletionResponseBuilder()
    generator = create_streaming_response(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model_id,
        messages=messages,
        # tools=REPORT_WRITTING_TOOLS,
        # tool_choice="auto"
    )

    async for chunk in arm.handle_streaming_response(
        wrapstream(generator, builder.add_chunk),
        cut_tags=["think", "ref", "refs"],
        cut_pats=[r'^#+\s*']
    ):
        if event.is_set():
            break

        if chunk.choices[0].delta.content:
            yield chunk

    completion = await builder.build()

    messages.append({
        "role": "assistant",
        "content": completion.choices[0].message.content,
        "tool_calls": [
            {}
        ]
    })

async def generate_high_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed report for CRITICAL and HIGH severity issues."""

    # Include both CRITICAL and HIGH severity
    critical_high_df = df[df['severity'].isin(['CRITICAL', 'HIGH'])]
    yield wrap_chunk(random_uuid(), f"\n## 🔴 Critical & High Severity Issues ({len(critical_high_df)} found)\n\n", "assistant")

    # Group by CWE for better organization
    grouped_by_cwe = critical_high_df.groupby('cwe')

    for cwe_id, group in grouped_by_cwe:
        if event.is_set():
            break

        async for chunk in _generate_cwe_detailed_analysis(cwe_id, group, repo, arm, event, is_critical=True):
            yield chunk

async def generate_medium_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed report for MEDIUM severity issues."""

    medium_df = df[df['severity'] == 'MEDIUM']
    yield wrap_chunk(random_uuid(), f"\n## 🟡 Medium Severity Issues ({len(medium_df)} found)\n\n", "assistant")

    # Group by CWE for better organization
    grouped_by_cwe = medium_df.groupby('cwe')

    for cwe_id, group in grouped_by_cwe:
        if event.is_set():
            break

        async for chunk in _generate_cwe_detailed_analysis(cwe_id, group, repo, arm, event, is_critical=False):
            yield chunk

async def generate_other_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate summary report for LOW severity and other issues."""

    other_df = df[~df['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM'])]
    yield wrap_chunk(random_uuid(), f"\n## 🟢 Low Severity & Other Issues ({len(other_df)} found)\n\n", "assistant")

    # For low severity, provide a summary grouped by CWE rather than individual analysis
    cwe_summary = other_df.groupby('cwe').agg({
        'tool': 'count',
        'file_path': lambda x: list(set(x)),
        'description': lambda x: list(x)[:3]  # First 3 examples
    }).rename(columns={'tool': 'count'})

    for cwe_id, row in cwe_summary.iterrows():
        if event.is_set():
            break

        count = row['count']
        files = row['file_path']
        examples = row['description']

        # Get CWE information
        cwe_info = get_cwe_by_id(cwe_id)
        cwe_name = f"CWE-{cwe_info.id}: {cwe_info.name}" if cwe_info else cwe_id

        yield wrap_chunk(random_uuid(), f"### {cwe_name}\n\n", "assistant")
        yield wrap_chunk(random_uuid(), f"**{count} occurrence(s)** across {len(files)} file(s)\n\n", "assistant")

        if cwe_info and cwe_info.description:
            yield wrap_chunk(random_uuid(), f"**Description:** {cwe_info.description}\n\n", "assistant")

        # Show affected files
        yield wrap_chunk(random_uuid(), "**Affected files:**\n", "assistant")
        for file in files[:5]:  # Limit to 5 files
            yield wrap_chunk(random_uuid(), f"- `{file}`\n", "assistant")

        if len(files) > 5:
            yield wrap_chunk(random_uuid(), f"- ... and {len(files) - 5} more files\n", "assistant")

        yield wrap_chunk(random_uuid(), "\n", "assistant")

    # Add LLM recommendations for low priority issues
    if not event.is_set() and len(other_df) > 0:
        yield wrap_chunk(random_uuid(), "\n### 💡 Next Steps\n\n", "assistant")

        async for chunk in _generate_low_priority_recommendations(other_df, repo, arm, event):
            if event.is_set():
                break
            yield chunk

async def _generate_low_priority_recommendations(
    df: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate LLM recommendations for low priority security issues."""

    if event.is_set():
        return

    # Prepare summary of all low priority issues
    total_issues = len(df)
    unique_cwes = df['cwe'].nunique()
    affected_files = df['file_path'].nunique()

    # Get top CWEs by frequency
    top_cwes = df['cwe'].value_counts().head(5)
    cwe_details = []

    for cwe_id, count in top_cwes.items():
        cwe_info = get_cwe_by_id(cwe_id)
        cwe_name = f"CWE-{cwe_info.id}: {cwe_info.name}" if cwe_info else str(cwe_id)
        cwe_details.append({
            "id": cwe_id,
            "name": cwe_name,
            "count": count,
            "description": cwe_info.description if cwe_info else "No description available"
        })

    # Get sample file paths and descriptions
    sample_issues = df.head(10)[['file_path', 'description', 'cwe', 'tool', 'line_start', 'line_end']]
    sample_issues['context'] = [
        repo.reveal_content(
            issue['file_path'],
            issue['line_start'],
            issue['line_end'],
            A=3, B=3
        )
        if repo else None
        for i, issue in sample_issues.iterrows()
    ]

    sample_issues = sample_issues[['file_path', 'description', 'cwe', 'tool', 'context']].to_dict('records')

    system_prompt = f"""You are a cybersecurity consultant providing strategic recommendations for managing low-priority security issues.

## Summary
- **Total low priority issues:** {total_issues}
- **Unique vulnerability types (CWEs):** {unique_cwes}
- **Affected files:** {affected_files}

## Top Vulnerability Types:
{json.dumps(cwe_details)}

## Sample Issues:
{json.dumps(sample_issues)}

## Task
Provide practical, prioritized recommendations for addressing these low-priority security issues. Your response should include:

1. **Risk Assessment**: Overall risk level and potential business impact of these low-priority issues
2. **Prioritization Strategy**: How to prioritize fixing these issues (by CWE type, file criticality, etc.)
3. **Remediation Approach**:
   - Quick wins that can be automated or batch-fixed
   - Issues that require manual review
   - Long-term prevention strategies
4. **Resource Planning**: Estimated effort and timeline recommendations
5. **Monitoring & Prevention**: How to prevent similar issues in the future
6. **Respond close to the context**: Reference to the current source code as much as possible

Keep your response practical, actionable, and focused on helping development teams efficiently address these issues. Use markdown formatting, bullet points for clarity and bold the headinngs. No intro needed.
"""

    messages = [
        {"role": "system", "content": system_prompt},
    ]

    builder = ChatCompletionResponseBuilder()
    generator = create_streaming_response(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model_id,
        messages=messages,
    )

    async for chunk in arm.handle_streaming_response(
        wrapstream(generator, builder.add_chunk),
        cut_tags=["think", "ref", "refs"],
        cut_pats=[r'^#+\s*']
    ):
        if event.is_set():
            break

        if chunk.choices[0].delta.content:
            yield chunk

async def _generate_cwe_detailed_analysis(
    cwe_id: str,
    group: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event,
    is_critical: bool = False
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed analysis for a specific CWE group."""

    # Get CWE information
    cwe_info = get_cwe_by_id(cwe_id)
    cwe_name = f"CWE-{cwe_info.id}: {cwe_info.name}" if cwe_info else cwe_id

    # Header
    icon = "🔥 " if is_critical else "⚠️ "
    yield wrap_chunk(random_uuid(), f"### {icon} {cwe_name}\n\n", "assistant")

    # CWE descriptionh
    if cwe_info:
        yield wrap_chunk(random_uuid(), f"**Description:** {cwe_info.description}\n\n", "assistant")

        if cwe_info.consequences:
            yield wrap_chunk(random_uuid(), f"**Potential Impact:** {', '.join(cwe_info.consequences[:3])}\n\n", "assistant")

    # Show each issue in detail
    for idx, (_, report) in enumerate(group.iterrows()):
        if event.is_set():
            break

        if idx >= 5 and not is_critical:  # Limit non-critical issues
            yield wrap_chunk(random_uuid(), f"*... and {len(group) - idx} more issues*\n\n", "assistant")
            break

        line_start = report['line_start'] or None
        line_end = report['line_end'] or None

        # Issue details
        line_info = f":{line_start}-{line_end}" if line_start and line_end and line_start != line_end else (
            "" if not report['line_number'] else f":{line_start}"
        )

        github_link = repo.get_reference(report['file_path'], line_start, line_end)
        yield wrap_chunk(random_uuid(), f"**Issue {idx + 1}:** [{report['file_path']}{line_info}]({github_link})\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Tool:** {report['tool']}\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Severity:** {report['severity']}\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Description:** {report['description']}\n", "assistant")

        # Show source code context if available
        if repo and report['file_path'] and report['line_number']:
            try:

                if line_start and line_end:
                    context = repo.reveal_content(report['file_path'], line_start, line_end, A=3, B=3)

                    if context:
                        yield wrap_chunk(random_uuid(), f"\n**Context:**\n```{report['language']}\n{context}\n```\n", "assistant")

            except Exception as e:
                logger.warning(f"Failed to get source context: {e}")

        yield wrap_chunk(random_uuid(), "\n", "assistant")

    # Generate LLM analysis for exploitation examples and fixes
    async for chunk in _generate_cwe_analysis_with_llm(cwe_info, group, repo, arm, event, is_critical):
        yield chunk

async def _generate_cwe_analysis_with_llm(
    cwe_info: CWEWeakness,
    group: DataFrame,
    repo: RepoInfo | None,
    arm: AgentResourceManager,
    event: asyncio.Event,
    is_critical: bool = False
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Use LLM to generate exploitation examples and remediation advice."""

    if event.is_set():
        return

    # Prepare context for LLM
    issues_context = []
    for _, report in group.iterrows():
        context = {
            "file": report['file_path'],
            "line_number": f"{report['line_start']}-{report['line_end']}",
            "tool": report['tool'],
            "description": report['description'],
            "language": report['language'],
            "information": report.get('information'),
            "processed_information": report.get('processed_information'),
            "context": repo.reveal_content(
                report['file_path'],
                report['line_start'],
                report['line_end'],
                A=3, B=3
            ) if repo else None
        }
        issues_context.append(context)

    system_prompt = f"""You are a cybersecurity expert analyzing security vulnerabilities.

CWE Information:
- ID: {cwe_info.id if cwe_info else 'Unknown'}
- Name: {cwe_info.name if cwe_info else 'Unknown'}
- Description: {cwe_info.description if cwe_info else 'No description available'}

Issues Found:
{json.dumps(issues_context, indent=2)}

Please provide:
1. **Real-world Exploitation Example**: A concrete example of how this vulnerability could be exploited by an attacker
2. **Remediation Steps**: Specific, actionable steps to fix this vulnerability type
3. **Prevention Tips**: Best practices to prevent this issue in the future

Keep your response focused, practical, and include code examples where relevant. Use markdown formatting, bullet points for clarity and bold the headinngs. No intro needed.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Generate the exploitation example and remediation advice for these security findings."}
    ]

    builder = ChatCompletionResponseBuilder()
    generator = create_streaming_response(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model_id,
        messages=messages,
    )

    async for chunk in arm.handle_streaming_response(
        wrapstream(generator, builder.add_chunk),
        cut_tags=["think", "ref", "refs"],
        cut_pats=[r'^#+\s*']
    ):
        if event.is_set():
            break

        if chunk.choices[0].delta.content:
            yield chunk
    yield wrap_chunk(random_uuid(), "\n---\n\n", "assistant")

async def generate_security_deep_report(
    confirmed_reports: list[Report],
    arm: AgentResourceManager,
    event: asyncio.Event,
    repo: RepoInfo | None = None
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    # Repo object is now passed as parameter

    report_list = [
        {
            "tool": report.tool,
            "severity": report.severity.value,
            "description": report.description,
            "file_path": report.file_path,
            "line_number": report.line_number,
            "line_start": report.line_start,
            "line_end": report.line_end,
            "language": report.language,
            "cwe": report.cwe,
            "cve": report.cve,
            "information": report.information,
            "processed_information": report.processed_information
        }
        for report in confirmed_reports
    ]

    df = pd.DataFrame(report_list)
    df['cwe'] = df['cwe'].apply(normalize_cwe)

    df['cwe'] = df['cwe'].apply(lambda x: [cwe.strip() for cwe in x.split(',')])
    df = df.explode('cwe').drop_duplicates()

    # Fix the filtering logic
    high_severity_df = df[df['severity'].isin(['CRITICAL', 'HIGH'])]
    medium_severity_df = df[df['severity'] == 'MEDIUM']
    other_df = df[~df['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM'])]

    async for chunk in generate_headline(df, repo, arm, event):
        yield chunk

    if len(high_severity_df) > 0:
        async for chunk in generate_high_severity_report(high_severity_df, repo, arm, event):
            yield chunk


    if len(medium_severity_df) > 0:
        async for chunk in generate_medium_severity_report(medium_severity_df, repo, arm, event):
            yield chunk

    if len(other_df) > 0:
        async for chunk in generate_other_severity_report(other_df, repo, arm, event):
            yield chunk

async def generate_security_report(
    confirmed_reports: list[Report],
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    yield wrap_chunk(random_uuid(), merge_reports(confirmed_reports), "assistant")

async def handoff(
    tool_name: str,
    tool_args: dict[str, Any],
    arm: AgentResourceManager,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse | FullyHandoff, None]:

    if tool_name not in fn_mapping:
        yield wrap_chunk(random_uuid(), f"{tool_name} not found", "assistant")
        return

    fn = fn_mapping[tool_name]
    confirmed_reports = []
    deep_mode = tool_args.get('deep', True)
    repo_url = tool_args.get('repo_url', None)
    target_path = tool_args.get('target_path', "")

    repo = None

    if repo_url is not None:
        repo = RepoInfo(clone_repo(repo_url, tool_args.get('branch', None)), target_path)

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
            report: Report | None = await confirm_report(report, confirmed_reports, deep_mode, repo)

            if report is None:
                continue

            confirmed_reports.append(report)

            yield wrap_chunk(
                random_uuid(),
                f"\n<details>\n<summary>{report.tool} found an issue - {report.severity} - {report.cwe or 'Unknown CWE'}</summary>\n```plain\n{fmt_report(report, repo)}\n```\n</details>\n",
                "assistant"
            )

    if not confirmed_reports:
        yield wrap_chunk(random_uuid(), f"Repository is well-secured, no issues found!", "assistant")
        return

    if deep_mode:
        yield FullyHandoff()

        async for chunk in generate_security_deep_report(confirmed_reports, arm, event, repo):
            yield chunk

    else:
        async for chunk in generate_security_report(confirmed_reports, event):
            yield chunk

async def execute_toolcall_request(
    tool_name: str,
    tool_args: dict[str, Any],
    arm: AgentResourceManager,
    event: asyncio.Event
) -> list[Union[TextContent, EmbeddedResource]] | AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    for tool in await source_code_mcp._mcp_list_tools():
        if tool.name == tool_name:
            return handoff(tool_name, tool_args, arm, event) # async generator, no need to await

    # Check diff_analysis_mcp tools
    for tool in await diff_analysis_mcp._mcp_list_tools():
        if tool.name == tool_name:
            return await execute_openai_compatible_toolcall(tool_name, tool_args, diff_analysis_mcp)

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
            result = await execute_toolcall_request(_name, _args, arm, event)

            if isinstance(result, AsyncGenerator):
                try:
                    fully_handoff = False

                    async for chunk in result:
                        if isinstance(chunk, FullyHandoff):
                            fully_handoff = True
                            continue

                        if isinstance(chunk, ErrorResponse):
                            raise Exception(chunk.message)

                        chunk_content = chunk.choices[0].delta.content or ""
                        striped_chunk_content = chunk_content.strip()

                        if fully_handoff or (
                            striped_chunk_content.startswith('<details>')
                            and striped_chunk_content.endswith('</details>')
                        ):
                            yield chunk

                        _result += chunk_content

                except Exception as e:
                    logger.error(f"Error executing toolcall: {e}", exc_info=True)
                    _result = f"Error executing toolcall: {e}"

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