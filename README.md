# AI-Powered DFIR Investigation Assistant

A Git-ready Phase 1 foundation for an evidence-grounded, confidence-aware Digital Forensics and Incident Response platform.

## Included in this starter build

- React + TypeScript + Vite frontend
- Tailwind-based SOC dashboard shell
- FastAPI backend
- PostgreSQL and SQLAlchemy configuration
- Health endpoint
- Case model and starter case endpoints
- Docker Compose development environment
- GitHub Actions CI
- Final project scope containing exactly the original feature set plus the eight approved research features

## Quick start

1. Copy `.env.example` to `.env`.
2. Run `docker compose up --build`.
3. Open the frontend at `http://localhost:5173`.
4. Open API documentation at `http://localhost:8000/docs`.

## Verify services

- Frontend: `http://localhost:5173`
- Backend health: `http://localhost:8000/api/v1/health`
- OpenAPI: `http://localhost:8000/docs`

## GitHub workflow

See `docs/GITHUB_WORKFLOW.md` for repository creation, commits and pushing.

## Current milestone

This is Phase 1 foundation code. Authentication, full RBAC, evidence ingestion and the eight research features are intentionally developed in later feature branches so each milestone can be tested and committed cleanly.
