"""OpenAI-compatible HTTP provider.

Speaks the ``/v1/chat/completions`` dialect used by OpenAI *and* the common local
runtimes (Ollama's OpenAI shim, vLLM, LM Studio, llama.cpp server) and many
authorized AI gateways. This is how AEGIS assesses a *real* target.

Requests only leave the process after passing the authorization scope guard in
:class:`~aegis.providers.base.Provider`. ``requests`` is an optional dependency;
if it is missing the provider raises a clear, actionable error rather than
importing at module load (keeping the core import-clean and offline).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from ..core.authorization import AuthorizationScope
from .base import Provider, ProviderRequest, ProviderResponse


class OpenAICompatProvider(Provider):
    name = "openai_compat"

    def __init__(
        self,
        endpoint: str,
        model: str,
        scope: Optional[AuthorizationScope] = None,
        api_key_env: str = "AEGIS_API_KEY",
        params: Optional[dict] = None,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(scope=scope, model=model, endpoint=endpoint, params=params)
        self.api_key_env = api_key_env
        self.timeout = timeout

    def _complete(self, req: ProviderRequest) -> ProviderResponse:
        try:
            import requests  # optional
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "OpenAICompatProvider needs 'requests' "
                "(pip install aegis-ai-security[extras])") from e

        url = (req.endpoint or self.endpoint).rstrip("/")
        if not url.endswith("/chat/completions"):
            url = url + "/v1/chat/completions" if "/v1" not in url else url + "/chat/completions"

        headers = {"Content-Type": "application/json"}
        key = os.environ.get(self.api_key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"

        body = {
            "model": req.model or self.model,
            "messages": req.as_messages(),
            **{k: v for k, v in (req.params or {}).items() if not k.startswith("_")},
        }
        resp = requests.post(url, headers=headers, data=json.dumps(body),
                             timeout=self.timeout)
        if resp.status_code >= 400:
            return ProviderResponse(error=f"HTTP {resp.status_code}: {resp.text[:300]}",
                                    raw={"status": resp.status_code})
        data = resp.json()
        try:
            text = data["choices"][0]["message"]["content"]
        except Exception:
            text = data.get("choices", [{}])[0].get("text", "")
        usage = data.get("usage", {})
        return ProviderResponse(
            text=text or "",
            raw=data,
            tokens={"prompt": usage.get("prompt_tokens", 0),
                    "completion": usage.get("completion_tokens", 0)},
            model=data.get("model", self.model),
        )
