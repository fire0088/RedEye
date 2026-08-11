"""AWS Bedrock access via the Converse API.

Converse normalises tool-use across model families (Anthropic, Llama, Mistral,
Nova, ...) so we don't have to special-case per-provider request bodies. We use
converse_stream for token streaming.
"""
from __future__ import annotations

import json
from typing import Any, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


PROVIDER_LABELS = {
    "anthropic": "Anthropic",
    "meta": "Meta",
    "mistral": "Mistral",
    "amazon": "Amazon",
    "cohere": "Cohere",
    "ai21": "AI21",
    "deepseek": "DeepSeek",
}


def available_profiles() -> list[str]:
    """AWS profile names from ~/.aws/config and ~/.aws/credentials."""
    try:
        return sorted(boto3.Session().available_profiles) or ["default"]
    except Exception:
        return ["default"]


class BedrockLLM:
    def __init__(self, profile: str, region: str) -> None:
        self.profile = profile
        self.region = region
        session_kwargs = {"region_name": region}
        if profile and profile != "default":
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        cfg = Config(retries={"max_attempts": 2, "mode": "standard"},
                     read_timeout=300, connect_timeout=15)
        self.runtime = self.session.client("bedrock-runtime", config=cfg)
        self.control = self.session.client("bedrock", config=cfg)

    # -- model discovery ----------------------------------------------------
    def list_models(self) -> list[dict]:
        """Return tool-capable, on-demand text models plus inference profiles.

        Each entry: {"id": <invoke id>, "label": str, "provider": str}.
        Newer models are often only reachable through an inference-profile id,
        so we surface those too.
        """
        models: list[dict] = []
        seen: set[str] = set()

        try:
            resp = self.control.list_foundation_models(byOutputModality="TEXT")
            for m in resp.get("modelSummaries", []):
                mid = m.get("modelId", "")
                if not mid or mid in seen:
                    continue
                modalities = m.get("outputModalities", [])
                if "TEXT" not in modalities:
                    continue
                inference = m.get("inferenceTypesSupported", [])
                if inference and "ON_DEMAND" not in inference:
                    # keep only if reachable via inference profile (handled below)
                    continue
                provider = (m.get("providerName") or mid.split(".")[0]).lower()
                seen.add(mid)
                models.append({
                    "id": mid,
                    "label": m.get("modelName", mid),
                    "provider": PROVIDER_LABELS.get(provider, provider.title()),
                })
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(_boto_msg(e)) from e

        # cross-region inference profiles (many current models need these)
        try:
            paginator = self.control.get_paginator("list_inference_profiles")
            for page in paginator.paginate():
                for p in page.get("inferenceProfileSummaries", []):
                    pid = p.get("inferenceProfileId", "")
                    if not pid or pid in seen:
                        continue
                    seen.add(pid)
                    prov = pid.split(".")[1] if "." in pid else pid.split(".")[0]
                    models.append({
                        "id": pid,
                        "label": p.get("inferenceProfileName", pid) + "  [profile]",
                        "provider": PROVIDER_LABELS.get(prov, prov.title()),
                    })
        except Exception:
            pass  # inference profiles are best-effort

        models.sort(key=lambda m: (m["provider"], m["label"]))
        return models

    # -- streaming converse -------------------------------------------------
    def converse_stream(
        self,
        model_id: str,
        system: str,
        messages: list[dict],
        tool_config: dict | None,
    ) -> Iterator[dict]:
        """Yield normalised streaming events:

        {"type": "text", "text": str}
        {"type": "tool_use", "id": str, "name": str, "input": dict}
        {"type": "stop", "reason": str, "message": <assistant message dict>}
        {"type": "error", "text": str}

        The assistant message dict (content blocks) is accumulated so callers
        can append it to history verbatim.
        """
        kwargs: dict[str, Any] = {
            "modelId": model_id,
            "messages": messages,
            "system": [{"text": system}] if system else [],
            "inferenceConfig": {"maxTokens": 2048, "temperature": 0.6},
        }
        if tool_config and tool_config.get("tools"):
            kwargs["toolConfig"] = tool_config

        try:
            resp = self.runtime.converse_stream(**kwargs)
        except (ClientError, BotoCoreError) as e:
            yield {"type": "error", "text": _boto_msg(e)}
            return

        content_blocks: list[dict] = []
        cur_text = ""
        cur_tool: dict | None = None
        cur_tool_json = ""
        stop_reason = "end_turn"

        try:
            for event in resp["stream"]:
                if "contentBlockStart" in event:
                    start = event["contentBlockStart"].get("start", {})
                    if "toolUse" in start:
                        cur_tool = {
                            "toolUseId": start["toolUse"]["toolUseId"],
                            "name": start["toolUse"]["name"],
                        }
                        cur_tool_json = ""
                elif "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"]["delta"]
                    if "text" in delta:
                        cur_text += delta["text"]
                        yield {"type": "text", "text": delta["text"]}
                    elif "toolUse" in delta:
                        cur_tool_json += delta["toolUse"].get("input", "")
                elif "contentBlockStop" in event:
                    if cur_tool is not None:
                        try:
                            parsed = json.loads(cur_tool_json) if cur_tool_json.strip() else {}
                        except json.JSONDecodeError:
                            parsed = {}
                        block = {"toolUse": {
                            "toolUseId": cur_tool["toolUseId"],
                            "name": cur_tool["name"],
                            "input": parsed,
                        }}
                        content_blocks.append(block)
                        yield {"type": "tool_use", "id": cur_tool["toolUseId"],
                               "name": cur_tool["name"], "input": parsed}
                        cur_tool = None
                    elif cur_text:
                        content_blocks.append({"text": cur_text})
                        cur_text = ""
                elif "messageStop" in event:
                    stop_reason = event["messageStop"].get("stopReason", "end_turn")
                elif "metadata" in event:
                    pass
        except (ClientError, BotoCoreError) as e:
            yield {"type": "error", "text": _boto_msg(e)}
            return

        if cur_text:
            content_blocks.append({"text": cur_text})

        yield {"type": "stop", "reason": stop_reason,
               "message": {"role": "assistant", "content": content_blocks}}


def _boto_msg(e: Exception) -> str:
    if isinstance(e, ClientError):
        err = e.response.get("Error", {})
        code = err.get("Code", "Error")
        msg = err.get("Message", str(e))
        return f"{code}: {msg}"
    return str(e)
