#!/usr/bin/env bash
# Reviewer front door: ./run.sh help lists one command per question.
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/autosut/run.sh" "$@"
