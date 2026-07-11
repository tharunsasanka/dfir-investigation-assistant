# Master Build Prompt — AI-Powered DFIR Investigation Assistant

## Role
Act as a senior full-stack engineer, DFIR specialist, security architect, database engineer, AI engineer, UI/UX designer and DevOps engineer. Build a modern, enterprise-style AI-powered Digital Forensics and Incident Response web application suitable for a high-distinction individual final-year project.

## Scope Lock
Retain every requirement in the original project specification. Add only the following eight approved features:

1. Evidence-to-Conclusion Traceability
2. Cross-Evidence Correlation Engine
3. Confidence-Aware AI Findings
4. Investigation Hypothesis Board
5. Alternative Explanation Generator
6. Investigation Replay Mode
7. Built-In Evaluation Laboratory
8. Forensic Provenance and Reproducibility

Do not add YARA, MISP, STIX/TAXII, CASE/UCO, memory forensics, disk forensics, mobile forensics, live endpoint containment or any other extended feature unless explicitly approved later.

## Goal
Build a commercial-looking SOC/DFIR platform that automates evidence analysis, attack timeline reconstruction, threat-intelligence correlation, MITRE ATT&CK mapping, IOC extraction, explainable AI assistance, risk scoring, attack graphing, chain of custody and professional PDF reporting.

## Frontend
Use React, TypeScript, Vite, Tailwind CSS, Framer Motion, React Router, TanStack React Query, React Hook Form, Zod, Recharts or Chart.js, React Flow, Heroicons and Lucide Icons.

The interface must use a premium dark cybersecurity design with glassmorphism, restrained neon blue/cyan accents, soft gradients, rounded cards, clean typography, professional spacing, subtle shadows, loading skeletons, responsive navigation and accessible forms.

Animations must be smooth and subtle: page transitions, card hover motion, animated counters, fade/slide entrances, progress animation, timeline movement, graph transitions and button feedback.

Prioritise desktop and large-screen SOC workflows while supporting laptop, tablet and mobile layouts.

## Backend
Use Python FastAPI, Pydantic, SQLAlchemy, Alembic, Pandas, NumPy, Regex and ReportLab. Use PostgreSQL. Apply a modular service/repository architecture with typed schemas, centralised error handling, structured logging, dependency injection and RESTful endpoints.

For the free prototype, use FastAPI BackgroundTasks and an analysis_jobs table rather than requiring paid worker infrastructure. Keep the architecture extensible so a queue can be introduced later.

## Original Pages
Build the original pages and modules:

- Landing page
- Login and forgot-password pages
- SOC dashboard
- Case management
- Evidence upload
- Evidence viewer
- Interactive timeline
- AI investigation interface
- MITRE ATT&CK mapping
- Threat-intelligence dashboard
- Attack graph
- Reports
- Chain of custody
- Investigator notes
- Audit logs
- User/role management
- Settings/profile

## Original Core Features
Implement the original core requirements:

- Secure login and JWT authentication
- Password hashing and refresh-token architecture
- User roles and RBAC
- Case management
- EVTX, Syslog, CSV and limited PCAP metadata upload
- Secure file validation and storage
- SHA-256 integrity verification
- Log parsing and normalisation
- Automated detection
- Timeline reconstruction
- MITRE ATT&CK mapping
- IOC extraction
- Threat-intelligence correlation
- Explainable AI findings
- AI investigation chat
- Risk scoring
- Attack story generation
- Interactive attack graph
- Chain of custody
- Investigator notes
- Executive dashboard
- Professional PDF reports
- Audit logs

## Approved Feature 1 — Evidence-to-Conclusion Traceability
Every important AI or automated finding must cite the exact evidence that supports it. Store and display evidence file, evidence ID, raw/normalised event ID, timestamp, source host, parser, detection rule, correlation result, MITRE technique and threat-intelligence result. Clicking a citation must open the source event. Provide a React Flow claim-to-evidence graph.

## Approved Feature 2 — Cross-Evidence Correlation Engine
Correlate events across EVTX, Syslog, CSV and supported PCAP metadata using username, IP address, hostname, process ID, parent process ID, file hash, domain, session/logon ID and timestamp proximity. Produce correlated attack sequences with supporting events, reasoning, time range, severity, confidence, users, devices and MITRE mappings.

## Approved Feature 3 — Confidence-Aware AI Findings
Assign each finding one of: Confirmed, High, Medium, Low or Unverified. Calculate confidence using supporting event count, independent evidence sources, rule reliability, threat-intelligence confidence, timeline consistency, contradictory evidence and data completeness. Show a transparent confidence-factor breakdown rather than an unexplained score.

## Approved Feature 4 — Investigation Hypothesis Board
Allow analysts and the AI to create hypotheses. Each hypothesis must contain a statement, creator, supporting evidence, contradicting evidence, missing evidence, related entities, confidence, notes and analyst verdict. Statuses: Proposed, Investigating, Confirmed, Rejected and Inconclusive.

## Approved Feature 5 — Alternative Explanation Generator
For suspicious activity, generate the primary interpretation, a plausible benign explanation, a plausible malicious alternative, supporting and contradicting evidence, required verification steps and current confidence. Clearly separate verified facts from assumptions.

## Approved Feature 6 — Investigation Replay Mode
Create a playback experience for the reconstructed incident. Include play, pause, previous/next event, speed, jump-to-stage and filters by user, device, severity and MITRE technique. Synchronise the timeline, attack graph, risk score, compromised users/devices, IOCs and current attack stage.

## Approved Feature 7 — Built-In Evaluation Laboratory
Allow labelled datasets and ground-truth events to be compared with system output. Measure accuracy, precision, recall, F1 score, false-positive/negative rates, investigation time, timeline reconstruction accuracy, IOC extraction accuracy, MITRE mapping accuracy, AI citation accuracy, confidence calibration, report generation time, data-reduction ratio, user satisfaction and System Usability Scale results. Provide confusion matrices, comparison charts and exportable evaluation results.

## Approved Feature 8 — Forensic Provenance and Reproducibility
Record original evidence hashes, ingestion date, parser name/version, rule name/version, correlation-engine version, AI provider/model, prompt-template version, processing parameters, generated artifact hashes, analyst modifications and report version. A Reproduce Analysis action must create a new analysis run using the recorded configuration without overwriting prior results.

## AI Requirements
The AI assistant must explain findings, answer investigator questions, summarise incidents, recommend remediation, generate investigation narratives and produce executive summaries in language understandable to junior analysts.

The AI must be evidence-grounded. It must cite events, state when evidence is insufficient, separate facts from assumptions and never invent evidence or intelligence results. Major findings require analyst approval before becoming confirmed.

Use a provider abstraction so the free prototype can use a free hosted provider when available, local Ollama during development and a deterministic mock provider for tests. The non-AI investigation pipeline must continue functioning when an AI quota is unavailable.

## Security
Implement JWT authentication, secure password hashing, RBAC, strict input validation, secure uploads, SQL-injection protection through parameterised ORM queries, XSS controls, suitable CSRF protection, audit logs, rate limits, CORS restrictions, secure headers, secret management and HTTPS-ready deployment. Uploaded evidence must never be executed.

## Database
Use PostgreSQL. Include original entities for users, roles, cases, evidence, logs/events, timeline events, AI responses, reports, chain of custody, IOCs, threat intelligence and notes. Add entities needed only for the eight approved features: finding evidence citations, correlation groups/events, confidence factors, hypotheses/hypothesis evidence, alternative explanations, replay sessions/events, evaluation datasets/runs/metrics and provenance/analysis runs.

## Free Development and Deployment Constraint
Use only free/open-source development dependencies. Keep the hosted demonstration compatible with free tiers: static frontend hosting, a free sleeping FastAPI service, free PostgreSQL/object storage limits and a free or local AI provider. Limit demonstration file size and dataset volume through environment configuration. Never require a paid API for core operation.

## GitHub Repository Workflow
All work must be made inside the existing Git repository. Never replace completed files without checking current code. Before changing code, inspect the repository structure and current branch.

For each milestone:

1. Create a feature branch from the latest main branch.
2. Implement one cohesive unit of work.
3. Add or update tests and documentation.
4. Run backend and frontend validation.
5. Review `git diff` and ensure secrets/evidence are excluded.
6. Commit using Conventional Commits.
7. Push the feature branch to GitHub.
8. Open or prepare a pull request summary.
9. Merge only after CI succeeds.

Use commit examples such as:

- `chore: initialize DFIR monorepo foundation`
- `feat(auth): add JWT login and role permissions`
- `feat(cases): implement case management API and UI`
- `feat(evidence): add secure upload and SHA-256 verification`
- `feat(correlation): correlate events across evidence sources`
- `feat(ai): add evidence-cited confidence-aware findings`
- `feat(evaluation): add manual versus automated analysis metrics`

Never commit `.env`, secrets, API keys, uploaded evidence, database files or production reports.

## CI Requirements
Add GitHub Actions that install dependencies, run Python syntax/tests, build the TypeScript frontend and block merging when validation fails. Later milestones should add linting, security scanning and integration tests.

## Build Phases

### Phase 1 — Foundation
Create the monorepo, Docker Compose environment, React/Vite frontend, FastAPI backend, PostgreSQL configuration, database migrations, health checks, dashboard shell, routing, API client, base case model, `.env.example`, README and CI workflow. Commit and push as `chore: initialize DFIR platform foundation`.

### Phase 2 — Authentication and Cases
Implement JWT/refresh tokens, password hashing, RBAC, protected routes, user administration and complete case CRUD. Commit and push in tested feature branches.

### Phase 3 — Evidence Pipeline
Implement secure uploads, SHA-256 verification, chain of custody, EVTX/Syslog/CSV parsing, normalisation, processing jobs and evidence viewer.

### Phase 4 — Detection, Timeline and Original Intelligence Features
Implement detections, IOC extraction, threat-intelligence correlation, timeline reconstruction, MITRE mapping, risk scoring and reports.

### Phase 5 — Eight Approved Research Features
Implement the eight approved features only, with tests, evaluation data and UI integration.

### Phase 6 — Hardening, Evaluation and Free Deployment
Complete testing, usability evaluation, research comparison, documentation, production builds and free-tier deployment configuration.

## Coding Rules
Use TypeScript strict mode and Python type hints. Generate complete runnable files, not disconnected snippets. Do not create decorative buttons without functionality. Do not keep mock data once a real endpoint exists. Preserve existing UI and functionality unless a change is required. Add tests for security-critical and research-critical logic.

## Immediate Instruction
Begin with Phase 1. Inspect the repository first, implement the foundation, run validation, commit the result locally, then provide the exact GitHub push command and pull-request summary. Do not begin Phase 2 until Phase 1 runs successfully.
