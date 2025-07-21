from app.oai_models import ChatCompletionRequest, ChatCompletionStreamResponse, ChatCompletionAdditionalParameters, ErrorResponse, random_uuid
from typing import AsyncGenerator, Optional, Any, Callable, Union
import asyncio
from app.oai_streaming import create_streaming_response, ChatCompletionResponseBuilder
from app.utils import AgentResourceManager
import logging
from app.configs import settings
from app.utils import refine_chat_history, wrap_chunk, refine_assistant_message, refine_mcp_response, execute_openai_compatible_toolcall
import os
import json
from mcp.types import TextContent, EmbeddedResource

logger = logging.getLogger(__name__)

async def wrapstream(
    streaming_iter: AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None], 
    callback: Callable[[ChatCompletionStreamResponse | ErrorResponse], None]
):
    async for chunk in streaming_iter:
        callback(chunk)

        if chunk.choices[0].delta.content:
            yield chunk

async def get_system_prompt(newest_message: Optional[str], personality: str = "", enable_memory: bool = True) -> str:
    if os.path.exists("system_prompt.txt"):
        with open("system_prompt.txt", "r") as f:
            return f.read()

    return ""

from src.agent_sentinel import mcp as git_action_mcp, audit_mcp as source_code_mcp

async def list_toolcalls() -> list[dict[str, Any]]: 
    return [
        *(await git_action_mcp._mcp_list_tools()),
        *(await source_code_mcp._mcp_list_tools())
    ]
    
print(asyncio.run(list_toolcalls()))

async def handoff(tool_name: str, tool_args: dict[str, Any]) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    yield

async def execute_toolcall_request(
    tool_name: str, 
    tool_args: dict[str, Any]
) -> list[Union[TextContent, EmbeddedResource]] | AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    for tool in source_code_mcp._mcp_list_tools():
        if tool.name == tool_name:
            return handoff(tool_name, tool_args)

    return await execute_openai_compatible_toolcall(tool_name, tool_args, git_action_mcp)

async def handle_request(
    request: ChatCompletionRequest, 
    event: asyncio.Event,
    additional_parameters: Optional[ChatCompletionAdditionalParameters] = None
) -> AsyncGenerator[ChatCompletionStreamResponse, None]:
    messages = request.messages
    assert len(messages) > 0, "No messages in the request"

    arm = AgentResourceManager()

    system_prompt = await get_system_prompt(messages[-1].content)
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
        has_success_toolcall = False
        
        toolcalls_requested = (completion.choices[0].message.tool_calls or [])

        for call_idx, call in enumerate(toolcalls_requested):
            if event.is_set():
                logger.info(f"[toolcall] Event signal received, stopping the request")
                break

            n_calls += 1

            _id, _name, _args = call.id, call.function.name, call.function.arguments
            _args: dict = json.loads(_args)
            _result = ""

            yield wrap_chunk(random_uuid(), f"<action>Analyzing...</action>", "assistant")
            
            result = await execute_toolcall_request(_name, _args)
            
            if isinstance(result, AsyncGenerator):
                if isinstance(chunk, ErrorResponse):
                    raise Exception(chunk.message)

                chunk_content = chunk.choices[0].delta.content or ""

                if chunk_content.startswith("<details>") and chunk_content.endswith("</details>"):
                    yield chunk
            else:
                _result = result

            _result = refine_mcp_response(_result, arm)

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