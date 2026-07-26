import hashlib
import json
from typing import (
    Any,
    Protocol,
)
from urllib.parse import urlparse

import httpx
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.core.config import (
    Settings,
    get_settings,
)


class AISummaryProviderError(
    RuntimeError,
):
    pass


class AISummaryProviderDisabledError(
    AISummaryProviderError,
):
    pass


class AISummaryProviderConfigurationError(
    AISummaryProviderError,
):
    pass


class AISummaryProviderTimeoutError(
    AISummaryProviderError,
):
    pass


class AISummaryProviderResponseError(
    AISummaryProviderError,
):
    pass


class AISummarySafeContext(
    BaseModel,
):
    case_id: str = Field(
        min_length=1,
        max_length=100,
    )

    case_title: str = Field(
        min_length=1,
        max_length=255,
    )

    case_severity: str = Field(
        min_length=1,
        max_length=50,
    )

    case_status: str = Field(
        min_length=1,
        max_length=50,
    )

    deterministic_executive_summary: (
        str
    ) = Field(
        min_length=1,
        max_length=12000,
    )

    deterministic_technical_narrative: (
        str
    ) = Field(
        min_length=1,
        max_length=20000,
    )

    incident_scope: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )

    technical_findings: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
        max_length=100,
    )

    mitre_coverage: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )

    recommended_actions: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
        max_length=50,
    )

    verified_facts: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
        max_length=100,
    )

    assumptions: list[
        dict[str, Any]
    ] = Field(
        default_factory=list,
        max_length=50,
    )

    limitations: list[str] = Field(
        default_factory=list,
        max_length=50,
    )


class AISummaryProviderOutput(
    BaseModel,
):
    executive_summary: str = Field(
        min_length=1,
        max_length=12000,
    )

    technical_narrative: str = Field(
        min_length=1,
        max_length=20000,
    )

    additional_limitations: list[
        str
    ] = Field(
        default_factory=list,
        max_length=20,
    )

    @field_validator(
        "executive_summary",
        "technical_narrative",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "The generated text cannot "
                "be empty."
            )

        return normalized

    @model_validator(
        mode="after",
    )
    def normalize_limitations(
        self,
    ) -> "AISummaryProviderOutput":
        normalized: list[str] = []

        for item in (
            self.additional_limitations
        ):
            value = item.strip()

            if (
                value
                and value
                not in normalized
            ):
                normalized.append(
                    value
                )

        self.additional_limitations = (
            normalized
        )

        return self


class AISummaryProviderResult(
    BaseModel,
):
    output: AISummaryProviderOutput

    provider_name: str = Field(
        min_length=1,
        max_length=100,
    )

    model_name: str = Field(
        min_length=1,
        max_length=150,
    )

    prompt_sha256: str = Field(
        min_length=64,
        max_length=64,
    )

    response_sha256: str = Field(
        min_length=64,
        max_length=64,
    )

    prompt_char_count: int = Field(
        ge=1,
    )

    response_byte_count: int = Field(
        ge=1,
    )

    total_duration_ns: int | None = (
        Field(
            default=None,
            ge=0,
        )
    )

    prompt_eval_count: int | None = (
        Field(
            default=None,
            ge=0,
        )
    )

    eval_count: int | None = Field(
        default=None,
        ge=0,
    )


class AISummaryProvider(
    Protocol,
):
    def generate(
        self,
        context: AISummarySafeContext,
    ) -> AISummaryProviderResult:
        ...


FORBIDDEN_CONTEXT_KEYS = {
    "source_snapshot",
    "raw_event",
    "raw_events",
    "raw_record",
    "raw_records",
    "raw_data",
    "raw_content",
    "evidence_content",
    "file_content",
    "stored_filename",
    "storage_path",
    "absolute_path",
    "file_path",
    "original_record",
}


def calculate_text_sha256(
    value: str | bytes,
) -> str:
    encoded = (
        value
        if isinstance(
            value,
            bytes,
        )
        else value.encode(
            "utf-8"
        )
    )

    return hashlib.sha256(
        encoded
    ).hexdigest()


def normalize_context_key(
    key: str,
) -> str:
    normalized = []
    previous_was_separator = False

    for character in key.strip():
        if character.isalnum():
            normalized.append(
                character.lower()
            )
            previous_was_separator = (
                False
            )

        elif not previous_was_separator:
            normalized.append("_")
            previous_was_separator = (
                True
            )

    return "".join(
        normalized
    ).strip("_")


def validate_safe_context_value(
    value: Any,
    path: str = "context",
) -> None:
    if isinstance(
        value,
        dict,
    ):
        for key, child_value in (
            value.items()
        ):
            normalized_key = (
                normalize_context_key(
                    str(key)
                )
            )

            if (
                normalized_key
                in FORBIDDEN_CONTEXT_KEYS
                or normalized_key
                .startswith("raw_")
                or normalized_key
                .endswith("_raw")
            ):
                raise (
                    AISummaryProviderConfigurationError(
                        "The AI context contains "
                        "a prohibited raw-evidence "
                        f"field at {path}."
                    )
                )

            validate_safe_context_value(
                child_value,
                (
                    f"{path}."
                    f"{normalized_key}"
                ),
            )

        return

    if isinstance(
        value,
        list,
    ):
        for index, child_value in (
            enumerate(value)
        ):
            validate_safe_context_value(
                child_value,
                f"{path}[{index}]",
            )


def build_provider_prompt(
    context: AISummarySafeContext,
) -> str:
    context_payload = (
        context.model_dump(
            mode="json"
        )
    )

    validate_safe_context_value(
        context_payload
    )

    serialized_context = json.dumps(
        context_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return (
        "You are a DFIR investigation "
        "writing assistant.\n\n"
        "Use only the supplied structured "
        "context. Do not invent evidence, "
        "events, identities, timestamps, "
        "malware, threat intelligence, "
        "attribution, root cause, impact, "
        "or MITRE ATT&CK mappings.\n\n"
        "Preserve all uncertainty. Clearly "
        "separate verified observations from "
        "assumptions. Never state that an "
        "incident is confirmed unless the "
        "context explicitly supports that "
        "conclusion.\n\n"
        "Improve only the executive summary "
        "and technical narrative. Do not "
        "change evidence counts, finding "
        "counts, confidence values, rule IDs, "
        "MITRE technique IDs, timestamps, "
        "hosts, usernames, IP addresses, "
        "process names, or recommended "
        "actions.\n\n"
        "The executive summary must be "
        "understandable to management while "
        "remaining technically accurate. "
        "The technical narrative must be "
        "suitable for a DFIR analyst and cite "
        "relevant rule IDs, event codes, and "
        "MITRE technique IDs when they exist "
        "in the context.\n\n"
        "Return only JSON matching the "
        "provided schema. Do not include "
        "Markdown or surrounding text.\n\n"
        "Structured context:\n"
        f"{serialized_context}"
    )


def validate_local_provider_url(
    settings: Settings,
) -> str:
    base_url = (
        settings.ai_local_base_url
        .strip()
        .rstrip("/")
    )

    parsed = urlparse(base_url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise (
            AISummaryProviderConfigurationError(
                "The local AI base URL must "
                "use HTTP or HTTPS."
            )
        )

    if (
        parsed.username is not None
        or parsed.password is not None
    ):
        raise (
            AISummaryProviderConfigurationError(
                "Credentials are not permitted "
                "inside the local AI base URL."
            )
        )

    hostname = (
        parsed.hostname or ""
    ).lower()

    allowed_hosts = set(
        settings
        .ai_local_allowed_host_list
    )

    is_localhost_subdomain = (
        hostname.endswith(
            ".localhost"
        )
    )

    if (
        not hostname
        or (
            hostname
            not in allowed_hosts
            and not is_localhost_subdomain
        )
    ):
        raise (
            AISummaryProviderConfigurationError(
                "The local AI host is not in "
                "AI_LOCAL_ALLOWED_HOSTS."
            )
        )

    if parsed.query or parsed.fragment:
        raise (
            AISummaryProviderConfigurationError(
                "The local AI base URL cannot "
                "contain a query or fragment."
            )
        )

    return base_url


class OllamaSummaryProvider:
    def __init__(
        self,
        settings: Settings | None = None,
        transport: (
            httpx.BaseTransport | None
        ) = None,
    ):
        self.settings = (
            settings
            or get_settings()
        )

        self.transport = transport

    def validate_configuration(
        self,
    ) -> tuple[
        str,
        str,
    ]:
        if (
            not self.settings
            .ai_local_enabled
        ):
            raise (
                AISummaryProviderDisabledError(
                    "Local AI summary generation "
                    "is disabled."
                )
            )

        model_name = (
            self.settings
            .ai_local_model
            .strip()
        )

        if not model_name:
            raise (
                AISummaryProviderConfigurationError(
                    "AI_LOCAL_MODEL must be "
                    "configured before local AI "
                    "generation can run."
                )
            )

        base_url = (
            validate_local_provider_url(
                self.settings
            )
        )

        return (
            base_url,
            model_name,
        )

    def build_request_payload(
        self,
        prompt: str,
        model_name: str,
    ) -> dict[str, Any]:
        return {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "format": (
                AISummaryProviderOutput
                .model_json_schema()
            ),
            "options": {
                "temperature": (
                    self.settings
                    .ai_local_temperature
                ),
            },
        }

    def read_response_bytes(
        self,
        endpoint: str,
        payload: dict[str, Any],
    ) -> bytes:
        timeout = httpx.Timeout(
            timeout=(
                self.settings
                .ai_local_timeout_seconds
            ),
            connect=(
                self.settings
                .ai_local_connect_timeout_seconds
            ),
        )

        try:
            with httpx.Client(
                timeout=timeout,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    endpoint,
                    json=payload,
                    headers={
                        "Accept":
                            "application/json",
                        "Content-Type":
                            "application/json",
                    },
                ) as response:
                    response.raise_for_status()

                    response_bytes = (
                        bytearray()
                    )

                    for chunk in (
                        response.iter_bytes()
                    ):
                        response_bytes.extend(
                            chunk
                        )

                        if (
                            len(response_bytes)
                            > self.settings
                            .ai_local_max_response_bytes
                        ):
                            raise (
                                AISummaryProviderResponseError(
                                    "The local AI "
                                    "response exceeded "
                                    "the configured "
                                    "size limit."
                                )
                            )

                    return bytes(
                        response_bytes
                    )

        except httpx.TimeoutException as error:
            raise (
                AISummaryProviderTimeoutError(
                    "The local AI provider "
                    "request timed out."
                )
            ) from error

        except httpx.HTTPStatusError as error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "returned HTTP status "
                    f"{error.response.status_code}."
                )
            ) from error

        except httpx.RequestError as error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "could not be reached."
                )
            ) from error

    def parse_response(
        self,
        response_bytes: bytes,
        prompt: str,
        configured_model_name: str,
    ) -> AISummaryProviderResult:
        try:
            response_text = (
                response_bytes.decode(
                    "utf-8"
                )
            )

        except UnicodeDecodeError as error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "returned invalid UTF-8."
                )
            ) from error

        try:
            response_payload = (
                json.loads(
                    response_text
                )
            )

        except json.JSONDecodeError as error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "returned invalid JSON."
                )
            ) from error

        if not isinstance(
            response_payload,
            dict,
        ):
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "returned an unexpected "
                    "response structure."
                )
            )

        provider_error = (
            response_payload.get(
                "error"
            )
        )

        if provider_error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "reported a generation "
                    "failure."
                )
            )

        generated_text = (
            response_payload.get(
                "response"
            )
        )

        if not isinstance(
            generated_text,
            str,
        ):
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "response did not contain "
                    "generated text."
                )
            )

        try:
            generated_output = (
                AISummaryProviderOutput
                .model_validate_json(
                    generated_text
                )
            )

        except (
            ValidationError,
            ValueError,
        ) as error:
            raise (
                AISummaryProviderResponseError(
                    "The local AI provider "
                    "returned output that does "
                    "not match the required "
                    "summary schema."
                )
            ) from error

        returned_model_name = (
            response_payload.get(
                "model"
            )
        )

        model_name = (
            returned_model_name.strip()
            if isinstance(
                returned_model_name,
                str,
            )
            and returned_model_name.strip()
            else configured_model_name
        )

        return AISummaryProviderResult(
            output=generated_output,
            provider_name=(
                self.settings
                .ai_local_provider_name
                .strip()
                or "ollama"
            ),
            model_name=model_name,
            prompt_sha256=(
                calculate_text_sha256(
                    prompt
                )
            ),
            response_sha256=(
                calculate_text_sha256(
                    response_bytes
                )
            ),
            prompt_char_count=(
                len(prompt)
            ),
            response_byte_count=(
                len(response_bytes)
            ),
            total_duration_ns=(
                response_payload.get(
                    "total_duration"
                )
                if isinstance(
                    response_payload.get(
                        "total_duration"
                    ),
                    int,
                )
                else None
            ),
            prompt_eval_count=(
                response_payload.get(
                    "prompt_eval_count"
                )
                if isinstance(
                    response_payload.get(
                        "prompt_eval_count"
                    ),
                    int,
                )
                else None
            ),
            eval_count=(
                response_payload.get(
                    "eval_count"
                )
                if isinstance(
                    response_payload.get(
                        "eval_count"
                    ),
                    int,
                )
                else None
            ),
        )

    def generate(
        self,
        context: AISummarySafeContext,
    ) -> AISummaryProviderResult:
        (
            base_url,
            model_name,
        ) = self.validate_configuration()

        prompt = build_provider_prompt(
            context
        )

        if (
            len(prompt)
            > self.settings
            .ai_local_max_prompt_chars
        ):
            raise (
                AISummaryProviderConfigurationError(
                    "The safe AI prompt exceeds "
                    "the configured character "
                    "limit."
                )
            )

        payload = (
            self.build_request_payload(
                prompt,
                model_name,
            )
        )

        response_bytes = (
            self.read_response_bytes(
                (
                    f"{base_url}"
                    "/api/generate"
                ),
                payload,
            )
        )

        return self.parse_response(
            response_bytes,
            prompt,
            model_name,
        )


def create_local_ai_summary_provider(
    settings: Settings | None = None,
    transport: (
        httpx.BaseTransport | None
    ) = None,
) -> OllamaSummaryProvider:
    return OllamaSummaryProvider(
        settings=settings,
        transport=transport,
    )