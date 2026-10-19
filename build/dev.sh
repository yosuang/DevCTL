#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

exec go run ./script/build.go bin/devctl
