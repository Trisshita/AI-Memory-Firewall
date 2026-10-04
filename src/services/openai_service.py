"""
AI Memory Firewall - OpenAI Service
===================================
Provides asynchronous and synchronous client integration with OpenAI's
Chat Completions API. Supports production API calls with automatic retry logic,
exponential backoff, and a robust deterministic mock provider for test suites
and offline environments.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized response from LLM generation."""
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = "stop"
    raw_response: Dict[str, Any] = field(default_factory=dict)
    is_mock: bool = False
    retry_count: int = 0


class OpenAIServiceError(Exception):
    """Base exception for OpenAI service errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Any] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class OpenAIService:
    """
    OpenAI Chat Completions integration service with retry resilience.
    
    Handles API authentication, request construction, exponential retry/timeout handling,
    and fallback deterministic simulation when running without an active API key.
    """

    DEFAULT_API_URL = "https://api.openai.com/v1/chat/completions"
    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        default_model: str = "gpt-4o-mini",
        timeout_seconds: float = 30.0,
        mock_mode: bool = False,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        # Determine provider and key
        resolved_key = api_key or settings.gemini_api_key or settings.openai_api_key
        self.api_key = resolved_key
        
        is_gemini = (
            bool(settings.gemini_api_key)
            or (resolved_key and resolved_key.startswith("AIzaSy"))
            or settings.llm_provider.lower() == "gemini"
        )

        if is_gemini:
            self.base_url = base_url or settings.llm_base_url or self.GEMINI_API_URL
            self.default_model = settings.llm_model or (
                "gemini-2.0-flash" if default_model == "gpt-4o-mini" else default_model
            )
        else:
            self.base_url = base_url or settings.llm_base_url or self.DEFAULT_API_URL
            self.default_model = settings.llm_model or default_model

        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        # Enable mock mode if explicitly requested or if key is placeholder/mock/unset
        raw_key = (self.api_key or "").strip().lower()
        self.mock_mode = (
            mock_mode
            or not self.api_key
            or raw_key.startswith("mock-")
            or "placeholder" in raw_key
            or "change-me" in raw_key
            or raw_key == "dev-secret-key-change-in-prod"
        )

    def is_mock_mode(self) -> bool:
        """Check if service is running in mock simulation mode."""
        return self.mock_mode

    def _generate_mock_completion(
        self,
        messages: List[Dict[str, str]],
        model: str,
        start_time: float,
        explicit_mock: Optional[str] = None,
        retry_count: int = 0,
    ) -> LLMResponse:
        """Generate a simulated LLM response for testing and offline environments."""
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        if explicit_mock is not None:
            content = explicit_mock
        else:
            last_message = messages[-1]["content"] if messages else ""
            if "hello" in last_message.lower() or "hi" in last_message.lower():
                content = "Hello! I am your AI assistant running through the AI Memory Firewall. How can I help you today?"
            elif "summarize" in last_message.lower():
                content = f"Summary: Processed context of {len(messages)} message(s) successfully."
            elif "who are you" in last_message.lower():
                content = "I am an enterprise AI agent protected by the AI Memory Firewall security gateway."
            else:
                content = f"I have received and processed your message safely: '{last_message[:80]}...'"

        prompt_tokens = sum(len(m.get("content", "").split()) for m in messages)
        completion_tokens = len(content.split())

        return LLMResponse(
            content=content,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
            finish_reason="stop",
            raw_response={"mock": True, "provider": "AI Memory Firewall Mock Provider"},
            is_mock=True,
            retry_count=retry_count,
        )

    def generate_chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        mock_response: Optional[str] = None,
    ) -> LLMResponse:
        """
        Synchronous chat completion call with exponential retry logic.
        """
        selected_model = model or self.default_model
        start_time = time.perf_counter()

        if mock_response is not None or self.is_mock_mode():
            return self._generate_mock_completion(
                messages=messages,
                model=selected_model,
                start_time=start_time,
                explicit_mock=mock_response,
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        last_exception: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(self.base_url, headers=headers, json=payload)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if response.status_code == 200:
                    data = response.json()
                    choice = data["choices"][0]
                    usage = data.get("usage", {})

                    return LLMResponse(
                        content=choice["message"]["content"],
                        model=data.get("model", selected_model),
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        latency_ms=latency_ms,
                        finish_reason=choice.get("finish_reason", "stop"),
                        raw_response=data,
                        is_mock=False,
                        retry_count=attempt - 1,
                    )

                if response.status_code in self.RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** (attempt - 1))
                    logger.warning(
                        "OpenAI returned status %d on attempt %d/%d; retrying in %.2fs",
                        response.status_code, attempt, self.max_retries, sleep_time
                    )
                    time.sleep(sleep_time)
                    continue

                logger.error("OpenAI API error %d: %s", response.status_code, response.text)
                raise OpenAIServiceError(
                    f"OpenAI API error: {response.text}",
                    status_code=response.status_code,
                    details=response.text,
                )

            except httpx.RequestError as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** (attempt - 1))
                    logger.warning(
                        "OpenAI network error '%s' on attempt %d/%d; retrying in %.2fs",
                        exc, attempt, self.max_retries, sleep_time
                    )
                    time.sleep(sleep_time)
                    continue

                logger.error("OpenAI network request failed after %d attempts: %s", self.max_retries, exc)
                raise OpenAIServiceError(f"Network error communicating with OpenAI: {exc}") from exc

        if last_exception:
            raise OpenAIServiceError(f"OpenAI service failed: {last_exception}") from last_exception

        raise OpenAIServiceError("OpenAI call failed after maximum retries.")

    async def generate_chat_completion_async(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        mock_response: Optional[str] = None,
    ) -> LLMResponse:
        """
        Asynchronous chat completion call with exponential retry logic.
        """
        selected_model = model or self.default_model
        start_time = time.perf_counter()

        if mock_response is not None or self.is_mock_mode():
            return self._generate_mock_completion(
                messages=messages,
                model=selected_model,
                start_time=start_time,
                explicit_mock=mock_response,
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        last_exception: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(self.base_url, headers=headers, json=payload)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if response.status_code == 200:
                    data = response.json()
                    choice = data["choices"][0]
                    usage = data.get("usage", {})

                    return LLMResponse(
                        content=choice["message"]["content"],
                        model=data.get("model", selected_model),
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        latency_ms=latency_ms,
                        finish_reason=choice.get("finish_reason", "stop"),
                        raw_response=data,
                        is_mock=False,
                        retry_count=attempt - 1,
                    )

                if response.status_code in self.RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** (attempt - 1))
                    logger.warning(
                        "OpenAI async returned status %d on attempt %d/%d; retrying in %.2fs",
                        response.status_code, attempt, self.max_retries, sleep_time
                    )
                    await asyncio.sleep(sleep_time)
                    continue

                logger.error("OpenAI async API error %d: %s", response.status_code, response.text)
                raise OpenAIServiceError(
                    f"OpenAI API error: {response.text}",
                    status_code=response.status_code,
                    details=response.text,
                )

            except httpx.RequestError as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    sleep_time = self.backoff_factor * (2 ** (attempt - 1))
                    logger.warning(
                        "OpenAI async network error '%s' on attempt %d/%d; retrying in %.2fs",
                        exc, attempt, self.max_retries, sleep_time
                    )
                    await asyncio.sleep(sleep_time)
                    continue

                logger.error("OpenAI async network request failed after %d attempts: %s", self.max_retries, exc)
                raise OpenAIServiceError(f"Network error communicating with OpenAI: {exc}") from exc

        if last_exception:
            raise OpenAIServiceError(f"OpenAI async service failed: {last_exception}") from last_exception

        raise OpenAIServiceError("OpenAI async call failed after maximum retries.")
