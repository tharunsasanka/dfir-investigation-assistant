import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.case import Case
from app.models.investigation_summary import (
    InvestigationSummary,
    InvestigationSummarySource,
    InvestigationSummaryStatus,
)
from app.schemas.investigation_summary import (
    InvestigationAssumption,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationRecommendedAction,
    InvestigationSummaryFinding,
    InvestigationSummaryGenerateRequest,
    InvestigationVerifiedFact,
)
from app.services.ai_summary_provider import (
    AISummaryProviderError,
    AISummaryProviderResult,
    AISummarySafeContext,
    create_local_ai_summary_provider,
)
from app.services.ai_summary_validation_service import (
    AISummaryValidationError,
    AISummaryValidationResult,
    validate_ai_summary_output_or_raise,
)
from app.services.forensic_timeline_service import (
    build_all_timeline_entries,
)
from app.services.investigation_summary_service import (
    UnsupportedSummaryProviderError,
    build_assumptions,
    build_evidence_references,
    build_executive_summary,
    build_incident_scope,
    build_limitations,
    build_mitre_coverage,
    build_output_payload,
    build_recommended_actions,
    build_source_snapshot,
    build_summary_findings,
    build_technical_narrative,
    build_verified_facts,
    calculate_confidence_score,
    calculate_sha256,
    enum_value,
    get_case_or_raise,
    get_next_version_number,
    utc_now,
)


SUPPORTED_GENERATION_SOURCES = {
    InvestigationSummarySource.deterministic,
    InvestigationSummarySource.local_ai,
}


def truncate_text(
    value: str,
    maximum_length: int,
) -> str:
    normalized = value.strip()

    if len(normalized) <= maximum_length:
        return normalized

    return normalized[
        :maximum_length
    ].rstrip()


def serialize_datetime(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    return value.isoformat()


def unique_strings(
    values: list[str],
) -> list[str]:
    unique: list[str] = []

    for item in values:
        normalized = item.strip()

        if (
            normalized
            and normalized not in unique
        ):
            unique.append(normalized)

    return unique


def build_safe_scope_payload(
    scope: InvestigationIncidentScope,
) -> dict[str, Any]:
    return {
        "total_timeline_entries":
            scope.total_timeline_entries,
        "log_event_count":
            scope.log_event_count,
        "security_finding_count":
            scope.security_finding_count,
        "event_correlation_count":
            scope.event_correlation_count,
        "case_audit_count":
            scope.case_audit_count,
        "evidence_custody_count":
            scope.evidence_custody_count,
        "evidence_count":
            scope.evidence_count,
        "critical_count":
            scope.critical_count,
        "high_count":
            scope.high_count,
        "first_activity_at":
            serialize_datetime(
                scope.first_activity_at
            ),
        "last_activity_at":
            serialize_datetime(
                scope.last_activity_at
            ),
        "affected_hosts":
            scope.affected_hosts[:50],
        "affected_usernames":
            scope.affected_usernames[:50],
        "observed_source_ips":
            scope.observed_source_ips[:50],
        "observed_destination_ips":
            scope.observed_destination_ips[
                :50
            ],
        "observed_processes":
            scope.observed_processes[:50],
    }


def build_safe_findings_payload(
    findings: list[
        InvestigationSummaryFinding
    ],
) -> list[dict[str, Any]]:
    payload: list[
        dict[str, Any]
    ] = []

    for finding in findings[:50]:
        payload.append(
            {
                "title":
                    truncate_text(
                        finding.title,
                        255,
                    ),
                "description":
                    truncate_text(
                        finding.description,
                        2000,
                    ),
                "severity":
                    enum_value(
                        finding.severity
                    ),
                "confidence":
                    finding.confidence,
                "rule_id":
                    finding.rule_id,
                "event_time":
                    serialize_datetime(
                        finding.event_time
                    ),
                "event_code":
                    finding.event_code,
                "source_type":
                    finding.source_type,
                "mitre_tactic":
                    finding.mitre_tactic,
                "mitre_technique_id":
                    finding
                    .mitre_technique_id,
                "mitre_technique_name":
                    finding
                    .mitre_technique_name,
            }
        )

    return payload


def build_safe_mitre_payload(
    coverage: InvestigationMitreCoverage,
) -> dict[str, Any]:
    return {
        "tactic_count":
            coverage.tactic_count,
        "technique_count":
            coverage.technique_count,
        "tactics":
            coverage.tactics[:50],
        "techniques": [
            {
                "tactic":
                    technique.tactic,
                "technique_id":
                    technique.technique_id,
                "technique_name":
                    technique.technique_name,
                "finding_count":
                    technique.finding_count,
                "correlation_count":
                    technique
                    .correlation_count,
                "related_rule_ids":
                    technique
                    .related_rule_ids[:50],
            }
            for technique
            in coverage.techniques[:50]
        ],
    }


def build_safe_actions_payload(
    actions: list[
        InvestigationRecommendedAction
    ],
) -> list[dict[str, Any]]:
    return [
        {
            "priority":
                enum_value(
                    action.priority
                ),
            "title":
                truncate_text(
                    action.title,
                    255,
                ),
            "description":
                truncate_text(
                    action.description,
                    2000,
                ),
            "rationale":
                truncate_text(
                    action.rationale,
                    2000,
                ),
            "related_rule_ids":
                action.related_rule_ids[
                    :50
                ],
            "related_mitre_technique_ids":
                action
                .related_mitre_technique_ids[
                    :50
                ],
        }
        for action in actions[:30]
    ]


def build_safe_facts_payload(
    facts: list[
        InvestigationVerifiedFact
    ],
) -> list[dict[str, Any]]:
    return [
        {
            "statement":
                truncate_text(
                    fact.statement,
                    2000,
                ),
            "source_type":
                fact.source_type,
            "confidence":
                fact.confidence,
        }
        for fact in facts[:50]
    ]


def build_safe_assumptions_payload(
    assumptions: list[
        InvestigationAssumption
    ],
) -> list[dict[str, Any]]:
    return [
        {
            "statement":
                truncate_text(
                    assumption.statement,
                    2000,
                ),
            "reason":
                truncate_text(
                    assumption.reason,
                    2000,
                ),
            "confidence":
                assumption.confidence,
        }
        for assumption
        in assumptions[:30]
    ]


def build_local_ai_safe_context(
    investigation_case: Case,
    deterministic_executive_summary: str,
    deterministic_technical_narrative: str,
    scope: InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
    mitre_coverage: InvestigationMitreCoverage,
    recommended_actions: list[
        InvestigationRecommendedAction
    ],
    verified_facts: list[
        InvestigationVerifiedFact
    ],
    assumptions: list[
        InvestigationAssumption
    ],
    limitations: list[str],
) -> AISummarySafeContext:
    return AISummarySafeContext(
        case_id=str(
            investigation_case.id
        ),
        case_title=truncate_text(
            investigation_case.title,
            255,
        ),
        case_severity=str(
            enum_value(
                investigation_case.severity
            )
        ),
        case_status=str(
            enum_value(
                investigation_case.status
            )
        ),
        deterministic_executive_summary=(
            truncate_text(
                deterministic_executive_summary,
                12000,
            )
        ),
        deterministic_technical_narrative=(
            truncate_text(
                deterministic_technical_narrative,
                20000,
            )
        ),
        incident_scope=(
            build_safe_scope_payload(
                scope
            )
        ),
        technical_findings=(
            build_safe_findings_payload(
                findings
            )
        ),
        mitre_coverage=(
            build_safe_mitre_payload(
                mitre_coverage
            )
        ),
        recommended_actions=(
            build_safe_actions_payload(
                recommended_actions
            )
        ),
        verified_facts=(
            build_safe_facts_payload(
                verified_facts
            )
        ),
        assumptions=(
            build_safe_assumptions_payload(
                assumptions
            )
        ),
        limitations=[
            truncate_text(
                limitation,
                2000,
            )
            for limitation
            in limitations[:30]
            if limitation.strip()
        ],
    )


def build_provider_audit_metadata(
    result: AISummaryProviderResult,
) -> dict[str, Any]:
    return {
        "local_ai_used": True,
        "fallback_applied": False,
        "provider_name":
            result.provider_name,
        "model_name":
            result.model_name,
        "prompt_sha256":
            result.prompt_sha256,
        "response_sha256":
            result.response_sha256,
        "prompt_char_count":
            result.prompt_char_count,
        "response_byte_count":
            result.response_byte_count,
        "total_duration_ns":
            result.total_duration_ns,
        "prompt_eval_count":
            result.prompt_eval_count,
        "eval_count":
            result.eval_count,
    }


def build_validated_provider_audit_metadata(
    result: AISummaryProviderResult,
    validation_result:
        AISummaryValidationResult,
) -> dict[str, Any]:
    metadata = (
        build_provider_audit_metadata(
            result
        )
    )

    metadata.update(
        {
            "validation_passed": True,
            "validation_issue_count":
                len(
                    validation_result
                    .issues
                ),
            "validation_checked_entity_count":
                validation_result
                .checked_entity_count,
            "validation_unsupported_entity_count":
                validation_result
                .unsupported_entity_count,
            "validation_unsupported_claim_count":
                validation_result
                .unsupported_claim_count,
            "validation_count_mismatch_count":
                validation_result
                .count_mismatch_count,
        }
    )

    return metadata


def build_fallback_audit_metadata(
    error: Exception,
    configured_provider: str,
    configured_model: str,
) -> dict[str, Any]:
    metadata: dict[
        str,
        Any,
    ] = {
        "local_ai_used": False,
        "fallback_applied": True,
        "requested_provider":
            configured_provider,
        "requested_model":
            configured_model,
        "fallback_error_type":
            error.__class__.__name__,
        "fallback_reason":
            str(error),
    }

    if isinstance(
        error,
        AISummaryValidationError,
    ):
        validation_result = (
            error.result
        )

        metadata.update(
            {
                "validation_passed":
                    False,
                "validation_issue_count":
                    len(
                        validation_result
                        .issues
                    ),
                "validation_issue_codes":
                    sorted(
                        {
                            issue.code
                            for issue
                            in validation_result
                            .issues
                        }
                    ),
                "validation_checked_entity_count":
                    validation_result
                    .checked_entity_count,
                "validation_unsupported_entity_count":
                    validation_result
                    .unsupported_entity_count,
                "validation_unsupported_claim_count":
                    validation_result
                    .unsupported_claim_count,
                "validation_count_mismatch_count":
                    validation_result
                    .count_mismatch_count,
            }
        )

    return metadata


def apply_local_ai_generation(
    investigation_case: Case,
    deterministic_executive_summary: str,
    deterministic_technical_narrative: str,
    scope: InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
    mitre_coverage: InvestigationMitreCoverage,
    recommended_actions: list[
        InvestigationRecommendedAction
    ],
    verified_facts: list[
        InvestigationVerifiedFact
    ],
    assumptions: list[
        InvestigationAssumption
    ],
    limitations: list[str],
) -> tuple[
    str,
    str,
    list[str],
    InvestigationSummarySource,
    str,
    str,
    dict[str, Any],
]:
    settings = get_settings()

    provider_name = (
        settings
        .ai_local_provider_name
        .strip()
        or "ollama"
    )

    configured_model = (
        settings.ai_local_model.strip()
    )

    context = (
        build_local_ai_safe_context(
            investigation_case=(
                investigation_case
            ),
            deterministic_executive_summary=(
                deterministic_executive_summary
            ),
            deterministic_technical_narrative=(
                deterministic_technical_narrative
            ),
            scope=scope,
            findings=findings,
            mitre_coverage=(
                mitre_coverage
            ),
            recommended_actions=(
                recommended_actions
            ),
            verified_facts=(
                verified_facts
            ),
            assumptions=assumptions,
            limitations=limitations,
        )
    )

    provider = (
        create_local_ai_summary_provider(
            settings=settings
        )
    )

    try:
        result = provider.generate(
            context
        )

        validation_result = (
            validate_ai_summary_output_or_raise(
                context,
                result.output,
            )
        )

    except (
        AISummaryProviderError,
        AISummaryValidationError,
    ) as error:
        if (
            not settings
            .ai_local_fallback_to_deterministic
        ):
            raise

        fallback_limitations = (
            unique_strings(
                limitations
                + [
                    (
                        "Local AI processing "
                        "was unavailable during "
                        "generation. The saved "
                        "summary uses the "
                        "deterministic fallback."
                    )
                ]
            )
        )

        return (
            deterministic_executive_summary,
            deterministic_technical_narrative,
            fallback_limitations,
            InvestigationSummarySource
            .deterministic,
            "deterministic-fallback",
            configured_model,
            build_fallback_audit_metadata(
                error,
                provider_name,
                configured_model,
            ),
        )

    enhanced_limitations = (
        unique_strings(
            limitations
            + result.output
            .additional_limitations
        )
    )

    return (
        result.output.executive_summary,
        result.output.technical_narrative,
        enhanced_limitations,
        InvestigationSummarySource
        .local_ai,
        result.provider_name,
        result.model_name,
        build_validated_provider_audit_metadata(
            result,
            validation_result,
        ),
    )


def generate_investigation_summary(
    db: Session,
    case_id: uuid.UUID,
    requested_by_user_id: uuid.UUID | None,
    request: InvestigationSummaryGenerateRequest,
) -> InvestigationSummary:
    if (
        request.generation_source
        not in SUPPORTED_GENERATION_SOURCES
    ):
        raise UnsupportedSummaryProviderError(
            "Only deterministic and local AI "
            "summary generation are currently "
            "enabled."
        )

    investigation_case = (
        get_case_or_raise(
            db,
            case_id,
        )
    )

    version_number = (
        get_next_version_number(
            db,
            case_id,
        )
    )

    started_at = utc_now()

    generation_parameters = dict(
        request.generation_parameters
    )

    generation_parameters.update(
        {
            "requested_generation_source":
                enum_value(
                    request
                    .generation_source
                ),
            "effective_generation_source":
                enum_value(
                    request
                    .generation_source
                ),
        }
    )

    summary = InvestigationSummary(
        case_id=case_id,
        version_number=version_number,
        status=(
            InvestigationSummaryStatus
            .generating
        ),
        generation_source=(
            request.generation_source
        ),
        title=(
            f"Investigation Summary "
            f"v{version_number}: "
            f"{investigation_case.title}"
        )[:255],
        provider_name=(
            request.provider_name.strip()
            or enum_value(
                request.generation_source
            )
        ),
        model_name=(
            request.model_name.strip()
        ),
        prompt_template_version=(
            request
            .prompt_template_version
        ),
        generation_parameters=(
            generation_parameters
        ),
        requested_by_user_id=(
            requested_by_user_id
        ),
        generation_started_at=(
            started_at
        ),
    )

    db.add(summary)
    db.commit()
    db.refresh(summary)

    try:
        entries = (
            build_all_timeline_entries(
                db,
                case_id,
            )
        )

        scope = build_incident_scope(
            entries
        )

        findings = (
            build_summary_findings(
                db,
                case_id,
            )
        )

        mitre_coverage = (
            build_mitre_coverage(
                findings
            )
        )

        evidence_references = (
            build_evidence_references(
                db,
                case_id,
            )
        )

        recommended_actions = (
            build_recommended_actions(
                scope,
                mitre_coverage,
                findings,
            )
        )

        verified_facts = (
            build_verified_facts(
                scope,
                findings,
                evidence_references,
            )
        )

        assumptions = build_assumptions(
            entries
        )

        limitations = build_limitations(
            scope,
            findings,
        )

        confidence_score = (
            calculate_confidence_score(
                scope,
                mitre_coverage,
            )
        )

        executive_summary = (
            build_executive_summary(
                investigation_case,
                scope,
                mitre_coverage,
            )
        )

        technical_narrative = (
            build_technical_narrative(
                scope,
                mitre_coverage,
            )
        )

        effective_source = (
            InvestigationSummarySource
            .deterministic
        )

        provider_name = (
            request.provider_name.strip()
            or "deterministic"
        )

        model_name = (
            request.model_name.strip()
        )

        provider_metadata: dict[
            str,
            Any
        ] = {
            "local_ai_used": False,
            "fallback_applied": False,
        }

        if (
            request.generation_source
            == InvestigationSummarySource
            .local_ai
        ):
            (
                executive_summary,
                technical_narrative,
                limitations,
                effective_source,
                provider_name,
                model_name,
                provider_metadata,
            ) = apply_local_ai_generation(
                investigation_case=(
                    investigation_case
                ),
                deterministic_executive_summary=(
                    executive_summary
                ),
                deterministic_technical_narrative=(
                    technical_narrative
                ),
                scope=scope,
                findings=findings,
                mitre_coverage=(
                    mitre_coverage
                ),
                recommended_actions=(
                    recommended_actions
                ),
                verified_facts=(
                    verified_facts
                ),
                assumptions=assumptions,
                limitations=limitations,
            )

        generation_parameters.update(
            provider_metadata
        )

        generation_parameters[
            "effective_generation_source"
        ] = enum_value(
            effective_source
        )

        source_snapshot = (
            build_source_snapshot(
                investigation_case,
                scope,
                findings,
                mitre_coverage,
                evidence_references,
            )
        )

        output_payload = (
            build_output_payload(
                title=summary.title,
                executive_summary=(
                    executive_summary
                ),
                technical_narrative=(
                    technical_narrative
                ),
                findings=findings,
                scope=scope,
                mitre_coverage=(
                    mitre_coverage
                ),
                evidence_references=(
                    evidence_references
                ),
                recommended_actions=(
                    recommended_actions
                ),
                verified_facts=(
                    verified_facts
                ),
                assumptions=assumptions,
                limitations=limitations,
                confidence_score=(
                    confidence_score
                ),
            )
        )

        summary.generation_source = (
            effective_source
        )

        summary.provider_name = (
            provider_name
        )

        summary.model_name = model_name

        summary.generation_parameters = (
            generation_parameters
        )

        summary.executive_summary = (
            executive_summary
        )

        summary.technical_narrative = (
            technical_narrative
        )

        summary.technical_findings = [
            item.model_dump(
                mode="json"
            )
            for item in findings
        ]

        summary.incident_scope = (
            scope.model_dump(
                mode="json"
            )
        )

        summary.mitre_coverage = (
            mitre_coverage.model_dump(
                mode="json"
            )
        )

        summary.evidence_references = [
            item.model_dump(
                mode="json"
            )
            for item
            in evidence_references
        ]

        summary.recommended_actions = [
            item.model_dump(
                mode="json"
            )
            for item
            in recommended_actions
        ]

        summary.verified_facts = [
            item.model_dump(
                mode="json"
            )
            for item in verified_facts
        ]

        summary.assumptions = [
            item.model_dump(
                mode="json"
            )
            for item in assumptions
        ]

        summary.limitations = (
            limitations
        )

        summary.confidence_score = (
            confidence_score
        )

        summary.source_snapshot = (
            source_snapshot
        )

        summary.source_snapshot_sha256 = (
            calculate_sha256(
                source_snapshot
            )
        )

        summary.output_sha256 = (
            calculate_sha256(
                output_payload
            )
        )

        summary.status = (
            InvestigationSummaryStatus
            .pending_review
        )

        summary.generation_completed_at = (
            utc_now()
        )

        summary.generation_error = ""

        db.commit()
        db.refresh(summary)

        return summary

    except Exception as error:
        db.rollback()

        failed_summary = db.get(
            InvestigationSummary,
            summary.id,
        )

        if failed_summary is not None:
            failed_summary.status = (
                InvestigationSummaryStatus
                .failed
            )

            failed_summary.generation_error = (
                str(error)
            )

            failed_summary.generation_completed_at = (
                utc_now()
            )

            db.commit()

        raise