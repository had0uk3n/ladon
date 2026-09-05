#!/usr/bin/env bash
set -euo pipefail

cargo test -p ladon-app --test agent_broker_unix --no-default-features --offline
cargo test -p ladon --tests --offline
