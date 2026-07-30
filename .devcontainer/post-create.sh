#!/usr/bin/env bash
set -euo pipefail

readonly budget=600
readonly started=$SECONDS
readonly state=./portunusmcp-quickstart
readonly env_file="$state/.env.quickstart"
readonly compose_file="$state/compose.quickstart.yml"

remaining() {
    local seconds=$((budget - (SECONDS - started)))
    ((seconds > 0)) || return 1
    printf '%s\n' "$seconds"
}

bounded() {
    local seconds
    seconds="$(remaining)" || {
        echo "Devcontainer setup exceeded ${budget}s." >&2
        return 124
    }
    timeout --foreground "${seconds}s" "$@"
}

namespace() {
    local value
    value="$(sed -n "s/^QUICKSTART_NAMESPACE='\\([^']*\\)'$/\\1/p" "$env_file")"
    [[ "$value" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 1
    printf '%s\n' "$value"
}

failure() {
    local status=$?
    local project=""
    local seconds
    ((status != 0)) || return
    trap - EXIT
    echo "Devcontainer setup failed; generated state was preserved." >&2
    if [[ -f "$env_file" && -f "$compose_file" ]]; then
        if seconds="$(remaining)" && [[ -x .venv/bin/portunusmcp ]]; then
            timeout --foreground "${seconds}s" \
                .venv/bin/portunusmcp --timeout "$seconds" doctor "$state" || true
        fi
        project="$(namespace 2>/dev/null || true)"
        if [[ -n "$project" ]]; then
            echo "State-preserving restart:" >&2
            printf '  docker compose --env-file %q -p %q -f %q up -d --wait --pull never\n' \
                "$env_file" "$project" "$compose_file" >&2
            echo "Destructive reset (deletes named volumes):" >&2
            printf '  docker compose --env-file %q -p %q -f %q down --volumes\n' \
                "$env_file" "$project" "$compose_file" >&2
        fi
        echo "Destructive generated-directory removal:" >&2
        printf '  rm -rf -- %q\n' "$state" >&2
    fi
    exit "$status"
}
trap failure EXIT

docker_deadline=$((SECONDS + 60))
until docker info >/dev/null 2>&1; do
    if ((SECONDS >= docker_deadline)); then
        echo "Docker daemon did not become ready within 60s." >&2
        false
    fi
    sleep 1
done

if [[ ! -x .venv/bin/python ]]; then
    bounded python -m venv .venv
fi
bounded .venv/bin/pip install --disable-pip-version-check --no-input -e .

if [[ ! -e "$state" ]]; then
    bounded docker build --tag portunusmcp:dev .
    seconds="$(remaining)"
    timeout --foreground "${seconds}s" \
        .venv/bin/portunusmcp --timeout "$seconds" quickstart \
        --upstream-image portunusmcp:dev \
        --allow-tool read_file \
        --arguments '{"path":"README.md"}' \
        --port 8000 \
        --output-dir "$state" \
        --command python sample_target/overscoped_server.py
    exit
fi

[[ -f "$env_file" && -f "$compose_file" && -f "$state/credentials.env" ]] || {
    echo "$state exists but is not a complete quickstart directory; refusing to replace it." >&2
    false
}
project="$(namespace)" || {
    echo "Could not read QUICKSTART_NAMESPACE from $env_file; refusing to replace it." >&2
    false
}
seconds="$(remaining)"
timeout --foreground "${seconds}s" \
    docker compose --env-file "$env_file" -p "$project" -f "$compose_file" \
    up -d --wait --wait-timeout "$seconds" --pull never
seconds="$(remaining)"
timeout --foreground "${seconds}s" \
    .venv/bin/portunusmcp --timeout "$seconds" doctor "$state"
