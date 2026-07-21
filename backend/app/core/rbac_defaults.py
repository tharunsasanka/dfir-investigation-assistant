PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("cases.read", "View investigation cases."),
    ("cases.create", "Create investigation cases."),
    ("cases.update", "Update investigation cases."),
    ("cases.delete", "Delete investigation cases."),
    ("cases.assign", "Assign investigators to cases."),

    ("evidence.read", "View evidence and metadata."),
    ("evidence.upload", "Upload digital evidence."),
    ("evidence.manage", "Update and organize evidence."),
    ("evidence.export", "Export evidence records."),

    ("timeline.read", "View forensic timelines."),
    ("timeline.generate", "Generate forensic timelines."),

    ("findings.read", "View investigation findings."),
    ("findings.create", "Create investigation findings."),
    ("findings.update", "Update investigation findings."),
    ("findings.approve", "Approve investigation findings."),
    ("ai_findings.generate", "Generate confidence-aware AI findings."),

    ("mitre.read", "View MITRE ATT&CK mappings."),
    ("mitre.map", "Create MITRE ATT&CK mappings."),

    ("traceability.read", "View evidence-to-conclusion traceability."),
    ("traceability.manage", "Manage evidence-to-conclusion links."),

    ("correlation.read", "View cross-evidence correlations."),
    ("correlation.run", "Run cross-evidence correlation analysis."),

    ("hypotheses.read", "View investigation hypotheses."),
    ("hypotheses.manage", "Create and update hypotheses."),

    ("alternatives.read", "View alternative explanations."),
    ("alternatives.generate", "Generate alternative explanations."),

    ("replay.read", "View investigation replay records."),
    ("replay.run", "Run investigation replay."),

    ("evaluation.read", "View evaluation laboratory results."),
    ("evaluation.run", "Run evaluation experiments."),

    ("provenance.read", "View provenance and reproducibility data."),
    ("provenance.export", "Export provenance records."),

    ("reports.read", "View investigation reports."),
    ("reports.generate", "Generate investigation reports."),
    ("reports.export", "Export investigation reports."),

    ("audit.read", "View audit logs."),

    ("users.read", "View system users."),
    ("users.manage", "Create and manage users."),
    ("roles.read", "View roles and permissions."),
    ("roles.manage", "Create and manage roles."),
)


ALL_PERMISSION_NAMES = tuple(
    permission_name
    for permission_name, _ in PERMISSIONS
)


ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "administrator": ALL_PERMISSION_NAMES,

    "lead_investigator": tuple(
        permission
        for permission in ALL_PERMISSION_NAMES
        if permission not in {
            "users.manage",
            "roles.manage",
        }
    ),

    "forensic_investigator": (
        "cases.read",
        "cases.create",
        "cases.update",
        "evidence.read",
        "evidence.upload",
        "evidence.manage",
        "timeline.read",
        "timeline.generate",
        "findings.read",
        "findings.create",
        "findings.update",
        "ai_findings.generate",
        "mitre.read",
        "mitre.map",
        "traceability.read",
        "traceability.manage",
        "correlation.read",
        "correlation.run",
        "hypotheses.read",
        "hypotheses.manage",
        "alternatives.read",
        "alternatives.generate",
        "replay.read",
        "replay.run",
        "provenance.read",
        "reports.read",
        "reports.generate",
    ),

    "soc_analyst": (
        "cases.read",
        "evidence.read",
        "timeline.read",
        "findings.read",
        "findings.create",
        "ai_findings.generate",
        "mitre.read",
        "mitre.map",
        "correlation.read",
        "correlation.run",
        "alternatives.read",
        "alternatives.generate",
        "reports.read",
    ),

    "case_reviewer": (
        "cases.read",
        "evidence.read",
        "timeline.read",
        "findings.read",
        "findings.approve",
        "mitre.read",
        "traceability.read",
        "correlation.read",
        "hypotheses.read",
        "alternatives.read",
        "replay.read",
        "evaluation.read",
        "provenance.read",
        "reports.read",
        "reports.generate",
        "reports.export",
        "audit.read",
    ),

    "read_only_auditor": (
        "cases.read",
        "evidence.read",
        "timeline.read",
        "findings.read",
        "mitre.read",
        "traceability.read",
        "correlation.read",
        "hypotheses.read",
        "alternatives.read",
        "replay.read",
        "evaluation.read",
        "provenance.read",
        "reports.read",
        "audit.read",
        "users.read",
        "roles.read",
    ),
}


ROLE_DESCRIPTIONS: dict[str, str] = {
    "administrator": "Full platform administration access.",
    "lead_investigator": "Leads cases and supervises investigations.",
    "forensic_investigator": "Examines evidence and produces findings.",
    "soc_analyst": "Investigates alerts and suspicious activity.",
    "case_reviewer": "Reviews findings, reports, and investigation quality.",
    "read_only_auditor": "Read-only access for auditing and compliance.",
}