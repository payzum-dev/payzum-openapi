#!/usr/bin/env bash
# Refresh openapi/payzum-v1.yaml from the source of truth in saas-core.
#
# The copy in this repo is exactly that — a copy. The authoritative file lives
# in the gateway repo, where a contract suite runs it against the live API. If
# the two drift, the SDKs generate types for an API that does not exist.
#
# Usage: ./scripts/sync-openapi.sh /path/to/saas-core/cloudflare-saas
set -euo pipefail

SRC_REPO="${1:?usage: $0 /path/to/saas-core/cloudflare-saas}"
SRC="$SRC_REPO/workers/payzum/gateway/openapi/payzum-v1.yaml"
DEST="$(cd "$(dirname "$0")/.." && pwd)/openapi/payzum-v1.yaml"

[ -f "$SRC" ] || { echo "not found: $SRC" >&2; exit 1; }

if cmp -s "$SRC" "$DEST"; then
  echo "already in sync ($(wc -l < "$DEST") lines)"
  exit 0
fi

echo "--- changes to be pulled in ---"
diff -u "$DEST" "$SRC" | head -60 || true
cp "$SRC" "$DEST"
echo "synced: $(wc -l < "$DEST") lines"
echo
echo "Next: regenerate SDK types and run their contract tests. A spec change"
echo "that nobody regenerates against is the same drift, one layer down."
