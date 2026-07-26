import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import app.api.v1.investigation_summaries as summary_api
from app.db.session import get_db
from app.main import app
from app.services.investigation_summary_service import (
    InvestigationSummaryNotFoundError,
    InvestigationSummaryStateError,
    UnsupportedSummaryProviderError,
)


CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
PARENT_SUMMARY_ID = uuid.uuid4()
USER_ID = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()
FINDING_ID = uuid.uuid4()

BASE_TIME = "2026-07-26T08:00:00+00:00"


@pytest.fixture(
    autouse=True,
)
def clear_dependency_overrides():
    app.dependency_overrides.clear()

    yield

    app.dependency_overrides.clear()


def get_summary_routes() -> list[
    APIRoute
]:
    return [
        route
        for route in app.routes
        if (
            isinstance(
                route,
                APIRoute,
            )
            and (
                "investigation-summaries"
                in route.path
            )
        )
    ]


def override_summary_dependencies(
    *,
    user_id: uuid.UUID = USER_ID,
    deny_permission: bool = False,
) -> None:
    database_session = object()

    app.dependency_overrides[
        get_db
    ] = lambda: database_session

    current_user = SimpleNamespace(
        id=user_id,
    )

    def provide_user():
        return current_user

    def deny_access():
        raise HTTPException(
            status_code=403,
            detail=(
                "The authenticated user does "
                "not have the required permission."
            ),
        )

    for route in get_summary_routes():
        for dependency in (
            route.dependant.dependencies
        ):
            dependency_call = (
                dependency.call
            )

            if dependency_call is get_db:
                continue

            app.dependency_overrides[
                dependency_call
            ] = (
                deny_access
                if deny_permission
                else provide_user
            )


def make_summary_payload(
    *,
    summary_id: uuid.UUID = SUMMARY_ID,
    parent_summary_id: (
        uuid.UUID | None
    ) = None,
    version_number: int = 1,
    summary_status: str = (
        "pending_review"
    ),
    generation_source: str = (
        "deterministic"
    ),
    reviewed_by_user_id: (
        uuid.UUID | None
    ) = None,
    review_notes: str = "",
    reviewed_at: str | None = None,
) -> dict:
    return {
        "id": str(summary_id),
        "case_id": str(CASE_ID),
        "parent_summary_id": (
            str(parent_summary_id)
            if parent_summary_id
            is not None
            else None
        ),
        "version_number":
            version_number,
        "status": summary_status,
        "generation_source":
            generation_source,
        "title": (
            "Investigation Summary "
            f"v{version_number}"
        ),
        "executive_summary": (
            "The available forensic "
            "records identify suspicious "
            "activity requiring analyst "
            "validation."
        ),
        "technical_narrative": (
            "Parsed events, automated "
            "findings and correlations "
            "were reviewed."
        ),
        "technical_findings": [
            {
                "title": (
                    "Suspicious PowerShell "
                    "activity"
                ),
                "description": (
                    "A suspicious PowerShell "
                    "command was detected."
                ),
                "severity": "high",
                "confidence": 90,
                "rule_id": (
                    "WINDOWS-POWERSHELL-001"
                ),
                "event_time": BASE_TIME,
                "evidence_id": (
                    str(EVIDENCE_ID)
                ),
                "parsed_event_id": None,
                "security_finding_id": (
                    str(FINDING_ID)
                ),
                "correlation_id": None,
                "event_code": "4688",
                "source_type": (
                    "windows_event"
                ),
                "mitre_tactic": (
                    "Execution"
                ),
                "mitre_technique_id": (
                    "T1059.001"
                ),
                "mitre_technique_name": (
                    "PowerShell"
                ),
                "indicators": {
                    "process_name":
                        "powershell.exe",
                },
            }
        ],
        "incident_scope": {
            "total_timeline_entries":
                5,
            "log_event_count": 2,
            "security_finding_count":
                1,
            "event_correlation_count":
                1,
            "case_audit_count": 1,
            "evidence_custody_count":
                0,
            "evidence_count": 1,
            "critical_count": 0,
            "high_count": 2,
            "first_activity_at":
                BASE_TIME,
            "last_activity_at":
                BASE_TIME,
            "affected_hosts": [
                "WORKSTATION-01"
            ],
            "affected_usernames": [
                "laura.chen"
            ],
            "observed_source_ips": [
                "203.0.113.50"
            ],
            "observed_destination_ips":
                [],
            "observed_processes": [
                "powershell.exe"
            ],
            "evidence_ids": [
                str(EVIDENCE_ID)
            ],
        },
        "mitre_coverage": {
            "tactic_count": 1,
            "technique_count": 1,
            "tactics": [
                "Execution"
            ],
            "techniques": [
                {
                    "tactic": (
                        "Execution"
                    ),
                    "technique_id": (
                        "T1059.001"
                    ),
                    "technique_name": (
                        "PowerShell"
                    ),
                    "finding_count": 1,
                    "correlation_count":
                        0,
                    "related_rule_ids": [
                        (
                            "WINDOWS-"
                            "POWERSHELL-001"
                        )
                    ],
                }
            ],
        },
        "evidence_references": [
            {
                "evidence_id": (
                    str(EVIDENCE_ID)
                ),
                "original_filename": (
                    "security-events.jsonl"
                ),
                "evidence_type": "log",
                "sha256": "a" * 64,
                "size_bytes": 2048,
                "source": (
                    "Workstation export"
                ),
                "collected_at":
                    BASE_TIME,
                "created_at": BASE_TIME,
                "related_event_count":
                    2,
                "related_finding_count":
                    1,
                "related_correlation_count":
                    1,
            }
        ],
        "recommended_actions": [
            {
                "priority": "immediate",
                "title": (
                    "Contain affected "
                    "accounts and systems"
                ),
                "description": (
                    "Restrict affected "
                    "identities and isolate "
                    "affected systems."
                ),
                "rationale": (
                    "High-severity activity "
                    "was identified."
                ),
                "related_rule_ids": [
                    (
                        "WINDOWS-"
                        "POWERSHELL-001"
                    )
                ],
                "related_mitre_technique_ids":
                    [
                        "T1059.001"
                    ],
                "related_evidence_ids": [
                    str(EVIDENCE_ID)
                ],
            }
        ],
        "verified_facts": [
            {
                "statement": (
                    "The case contains five "
                    "unified timeline entries."
                ),
                "source_type": (
                    "forensic_timeline"
                ),
                "source_ids": [],
                "confidence": 100,
            }
        ],
        "assumptions": [],
        "limitations": [
            (
                "Automated findings require "
                "analyst validation."
            )
        ],
        "confidence_score": 85,
        "provider_name":
            generation_source,
        "model_name": "",
        "prompt_template_version":
            "1.0.0",
        "generation_parameters": {},
        "source_snapshot": {
            "case": {
                "id": str(CASE_ID),
            },
        },
        "source_snapshot_sha256":
            "b" * 64,
        "output_sha256": "c" * 64,
        "requested_by_user_id":
            str(USER_ID),
        "reviewed_by_user_id": (
            str(reviewed_by_user_id)
            if reviewed_by_user_id
            is not None
            else None
        ),
        "review_notes": review_notes,
        "generation_error": "",
        "generation_started_at":
            BASE_TIME,
        "generation_completed_at":
            BASE_TIME,
        "reviewed_at": reviewed_at,
        "created_at": BASE_TIME,
        "updated_at": BASE_TIME,
    }


def make_revision_request() -> dict:
    return {
        "title": (
            "Analyst Investigation "
            "Summary v2"
        ),
        "executive_summary": (
            "The analyst validated the "
            "identified suspicious activity."
        ),
        "technical_narrative": (
            "The original evidence and "
            "timeline records were manually "
            "reviewed."
        ),
        "technical_findings": [],
        "incident_scope": {
            "total_timeline_entries":
                5,
            "evidence_count": 1,
        },
        "mitre_coverage": {
            "tactic_count": 0,
            "technique_count": 0,
            "tactics": [],
            "techniques": [],
        },
        "evidence_references": [],
        "recommended_actions": [],
        "verified_facts": [],
        "assumptions": [],
        "limitations": [
            (
                "Additional endpoint "
                "telemetry was unavailable."
            )
        ],
        "confidence_score": 95,
    }


def test_generation_requires_authentication(
    client: TestClient,
    monkeypatch,
) -> None:
    def unexpected_service_call(
        **_kwargs,
    ):
        raise AssertionError(
            "The generation service must "
            "not run without authentication."
        )

    monkeypatch.setattr(
        summary_api,
        "generate_investigation_summary",
        unexpected_service_call,
    )

    response = client.post(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries/"
            "generate"
        ),
        json={},
    )

    assert response.status_code == 401


def test_generation_requires_permission(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies(
        deny_permission=True,
    )

    def unexpected_service_call(
        **_kwargs,
    ):
        raise AssertionError(
            "The generation service must "
            "not run without permission."
        )

    monkeypatch.setattr(
        summary_api,
        "generate_investigation_summary",
        unexpected_service_call,
    )

    response = client.post(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries/"
            "generate"
        ),
        json={},
    )

    assert response.status_code == 403


def test_generates_investigation_summary(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    def fake_generate(
        **kwargs,
    ):
        captured.update(kwargs)

        return make_summary_payload()

    monkeypatch.setattr(
        summary_api,
        "generate_investigation_summary",
        fake_generate,
    )

    response = client.post(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries/"
            "generate"
        ),
        json={
            "generation_source":
                "deterministic",
            "provider_name":
                "deterministic",
            "model_name": "",
            "prompt_template_version":
                "1.0.0",
            "generation_parameters": {
                "include_low_severity":
                    True,
            },
        },
    )

    assert response.status_code == 201

    response_data = response.json()

    assert (
        response_data["case_id"]
        == str(CASE_ID)
    )

    assert (
        response_data["status"]
        == "pending_review"
    )

    assert (
        response_data[
            "generation_source"
        ]
        == "deterministic"
    )

    assert (
        response_data[
            "confidence_score"
        ]
        == 85
    )

    assert (
        captured["case_id"]
        == CASE_ID
    )

    assert (
        captured[
            "requested_by_user_id"
        ]
        == USER_ID
    )

    assert (
        captured[
            "request"
        ].generation_source.value
        == "deterministic"
    )

    assert (
        captured[
            "request"
        ].generation_parameters[
            "include_low_severity"
        ]
        is True
    )


def test_generation_rejects_unsupported_provider(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    def fake_generate(
        **_kwargs,
    ):
        raise UnsupportedSummaryProviderError(
            "Only deterministic summary "
            "generation is currently enabled."
        )

    monkeypatch.setattr(
        summary_api,
        "generate_investigation_summary",
        fake_generate,
    )

    response = client.post(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries/"
            "generate"
        ),
        json={
            "generation_source":
                "local_ai",
            "provider_name": "local",
            "model_name":
                "local-test-model",
        },
    )

    assert response.status_code == 422

    assert response.json()["detail"] == (
        "Only deterministic summary "
        "generation is currently enabled."
    )


def test_generation_returns_missing_case(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    def fake_generate(
        **_kwargs,
    ):
        raise InvestigationSummaryNotFoundError(
            "Case not found."
        )

    monkeypatch.setattr(
        summary_api,
        "generate_investigation_summary",
        fake_generate,
    )

    response = client.post(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries/"
            "generate"
        ),
        json={},
    )

    assert response.status_code == 404
    assert (
        response.json()["detail"]
        == "Case not found."
    )


def test_lists_case_summary_versions(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    def fake_list(
        **kwargs,
    ):
        captured.update(kwargs)

        return {
            "items": [
                make_summary_payload()
            ],
            "total": 1,
            "page": 2,
            "page_size": 5,
            "pages": 1,
        }

    monkeypatch.setattr(
        summary_api,
        "list_case_investigation_summaries",
        fake_list,
    )

    response = client.get(
        (
            f"/api/v1/cases/{CASE_ID}"
            "/investigation-summaries"
            "?page=2&page_size=5"
        )
    )

    assert response.status_code == 200

    response_data = response.json()

    assert response_data["total"] == 1
    assert response_data["page"] == 2

    assert (
        response_data["page_size"]
        == 5
    )

    assert len(
        response_data["items"]
    ) == 1

    assert (
        captured["case_id"]
        == CASE_ID
    )

    assert captured["page"] == 2
    assert captured["page_size"] == 5


def test_retrieves_investigation_summary(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    def fake_get(
        **kwargs,
    ):
        captured.update(kwargs)

        return make_summary_payload()

    monkeypatch.setattr(
        summary_api,
        "get_investigation_summary",
        fake_get,
    )

    response = client.get(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}"
        )
    )

    assert response.status_code == 200

    assert (
        response.json()["id"]
        == str(SUMMARY_ID)
    )

    assert (
        captured["summary_id"]
        == SUMMARY_ID
    )


def test_retrieval_returns_missing_summary(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    def fake_get(
        **_kwargs,
    ):
        raise InvestigationSummaryNotFoundError(
            (
                "Investigation summary "
                "not found."
            )
        )

    monkeypatch.setattr(
        summary_api,
        "get_investigation_summary",
        fake_get,
    )

    response = client.get(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}"
        )
    )

    assert response.status_code == 404

    assert response.json()["detail"] == (
        "Investigation summary not found."
    )


def test_approves_pending_summary(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    def fake_review(
        **kwargs,
    ):
        captured.update(kwargs)

        return make_summary_payload(
            summary_status="approved",
            reviewed_by_user_id=(
                USER_ID
            ),
            review_notes=(
                "Validated against the "
                "original evidence."
            ),
            reviewed_at=BASE_TIME,
        )

    monkeypatch.setattr(
        summary_api,
        "review_investigation_summary",
        fake_review,
    )

    response = client.post(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}/review"
        ),
        json={
            "decision": "approved",
            "review_notes": (
                "Validated against the "
                "original evidence."
            ),
        },
    )

    assert response.status_code == 200

    response_data = response.json()

    assert (
        response_data["status"]
        == "approved"
    )

    assert (
        response_data[
            "reviewed_by_user_id"
        ]
        == str(USER_ID)
    )

    assert (
        captured[
            "reviewed_by_user_id"
        ]
        == USER_ID
    )

    assert (
        captured["decision"].value
        == "approved"
    )


def test_rejects_pending_summary(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    def fake_review(
        **kwargs,
    ):
        captured.update(kwargs)

        return make_summary_payload(
            summary_status="rejected",
            reviewed_by_user_id=(
                USER_ID
            ),
            review_notes=(
                "The scope requires "
                "additional evidence."
            ),
            reviewed_at=BASE_TIME,
        )

    monkeypatch.setattr(
        summary_api,
        "review_investigation_summary",
        fake_review,
    )

    response = client.post(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}/review"
        ),
        json={
            "decision": "rejected",
            "review_notes": (
                "The scope requires "
                "additional evidence."
            ),
        },
    )

    assert response.status_code == 200

    assert (
        response.json()["status"]
        == "rejected"
    )

    assert (
        captured["decision"].value
        == "rejected"
    )

    assert (
        captured["review_notes"]
        == (
            "The scope requires "
            "additional evidence."
        )
    )


def test_review_returns_state_conflict(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    def fake_review(
        **_kwargs,
    ):
        raise InvestigationSummaryStateError(
            "Only summaries pending review "
            "can be approved or rejected."
        )

    monkeypatch.setattr(
        summary_api,
        "review_investigation_summary",
        fake_review,
    )

    response = client.post(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}/review"
        ),
        json={
            "decision": "approved",
            "review_notes": "",
        },
    )

    assert response.status_code == 409

    assert response.json()["detail"] == (
        "Only summaries pending review "
        "can be approved or rejected."
    )


def test_creates_analyst_revision(
    client: TestClient,
    monkeypatch,
) -> None:
    override_summary_dependencies()

    captured: dict = {}

    revision_id = uuid.uuid4()

    def fake_revision(
        **kwargs,
    ):
        captured.update(kwargs)

        return make_summary_payload(
            summary_id=revision_id,
            parent_summary_id=(
                SUMMARY_ID
            ),
            version_number=2,
            generation_source=(
                "analyst"
            ),
        )

    monkeypatch.setattr(
        summary_api,
        "create_analyst_revision",
        fake_revision,
    )

    response = client.post(
        (
            "/api/v1/"
            "investigation-summaries/"
            f"{SUMMARY_ID}/revisions"
        ),
        json=make_revision_request(),
    )

    assert response.status_code == 201

    response_data = response.json()

    assert (
        response_data["id"]
        == str(revision_id)
    )

    assert (
        response_data[
            "parent_summary_id"
        ]
        == str(SUMMARY_ID)
    )

    assert (
        response_data[
            "version_number"
        ]
        == 2
    )

    assert (
        response_data[
            "generation_source"
        ]
        == "analyst"
    )

    assert (
        captured["summary_id"]
        == SUMMARY_ID
    )

    assert (
        captured[
            "requested_by_user_id"
        ]
        == USER_ID
    )

    assert (
        captured[
            "request"
        ].confidence_score
        == 95
    )