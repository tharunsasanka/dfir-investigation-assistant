#!/usr/bin/env bash
set -euo pipefail
python -m compileall backend/app
printf 'Python syntax verification passed.\n'
