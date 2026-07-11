# GitHub Commit Workflow

## Create and push the repository

```bash
git init
git add .
git commit -m "chore: initialize DFIR platform foundation"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/dfir-investigation-assistant.git
git push -u origin main
```

## Branch strategy

Use one branch per milestone:

```bash
git checkout -b feature/auth-rbac
git checkout -b feature/case-management
git checkout -b feature/evidence-pipeline
git checkout -b feature/correlation-engine
git checkout -b feature/explainable-ai
git checkout -b feature/evaluation-lab
```

## Required commit rule

After each verified unit of work:

```bash
git status
git add .
git commit -m "feat: describe the completed change"
git push -u origin CURRENT_BRANCH
```

Open a pull request, ensure CI passes, then merge into `main`.

## Recommended conventional commits

- `feat:` new feature
- `fix:` bug fix
- `test:` tests
- `docs:` documentation
- `refactor:` code restructuring
- `chore:` tooling, configuration or maintenance

Never commit `.env`, secrets, API keys, uploaded evidence or database data.
