"""Chat Completions transport with bounded provider fallbacks."""
import json
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from groq import Groq, APIError, APIStatusError


class ProviderError(Exception):
    pass


class Cancelled(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ModelRouter:
    def __init__(self, settings):
        self.settings = settings
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        )

    def _request(self, provider, payload):
        if urlsplit(provider.base_url).hostname == "api.groq.com":
            with Groq(
                api_key=provider.key,
                base_url="https://api.groq.com",
                timeout=self.settings.provider_timeout,
                max_retries=0,
            ) as client:
                response = client.chat.completions.create(**payload)
                data = response.model_dump(mode="json")

            if len(json.dumps(data).encode()) > 2_000_000:
                raise ProviderError("Response exceeded local limit")

            return data

        request = urllib.request.Request(
            provider.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": "Bearer " + provider.key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "PersonalCyberAssistant/1.0",
            },
            method="POST",
        )

        with self.opener.open(
            request,
            timeout=self.settings.provider_timeout,
        ) as response:
            body = response.read(2_000_001)

        if len(body) > 2_000_000:
            raise ProviderError("Response exceeded local limit")

        return json.loads(body)

    def complete(self, messages, kind, event, cancel, tools=None):
        candidates = [
            provider
            for provider in self.settings.providers.get(kind, [])
            if not tools or provider.tools
        ]

        if not candidates:
            raise ProviderError(
                f"No configured {kind} provider. "
                "Set API keys and model IDs in chatbot/.env."
            )

        for index, provider in enumerate(candidates):
            if cancel.is_set():
                raise Cancelled()

            event(f"Calling {provider.name} / {provider.model}")

            payload = {
                "model": provider.model,
                "messages": messages,
                "stream": False,
                provider.token_field: 4096,
            }

            if tools:
                payload.update({
                    "tools": tools,
                    "tool_choice": "auto",
                })

            remaining = index + 1 < len(candidates)
            next_action = (
                "trying configured fallback."
                if remaining
                else "no further configured fallback."
            )

            try:
                data = self._request(provider, payload)

                if cancel.is_set():
                    raise Cancelled()

                message = data["choices"][0]["message"]

                if not isinstance(message, dict):
                    raise ValueError("Invalid message")

                provider_id = provider.name + "/" + provider.model
                refusal = message.get("refusal")

                if refusal:
                    if not isinstance(refusal, str):
                        raise ValueError("Invalid refusal")

                    return {
                        "role": "assistant",
                        "content": refusal,
                    }, provider_id

                content = message.get("content")
                calls = message.get("tool_calls")

                if not isinstance(content, (str, type(None))):
                    raise ValueError("Invalid completion content")

                if not isinstance(calls, (list, type(None))):
                    raise ValueError("Invalid tool calls")

                if not content and not calls:
                    raise ValueError("Empty completion")

                result = {
                    "role": "assistant",
                    "content": content,
                }

                if calls:
                    result["tool_calls"] = calls

                return result, provider_id

            except APIStatusError as exc:
                event(
                    f"{provider.name} returned HTTP "
                    f"{exc.status_code}; {next_action}"
                )

            except urllib.error.HTTPError as exc:
                event(
                    f"{provider.name} returned HTTP "
                    f"{exc.code}; {next_action}"
                )

            except (
                APIError,
                urllib.error.URLError,
                TimeoutError,
                socket.timeout,
                OSError,
                KeyError,
                IndexError,
                TypeError,
                ValueError,
                ProviderError,
            ):
                event(
                    f"{provider.name} unavailable or returned "
                    f"an invalid response; {next_action}"
                )

            if cancel.is_set():
                raise Cancelled()

        raise ProviderError(
            "All configured providers failed. Review account access, "
            "model IDs, quota and connectivity."
        )