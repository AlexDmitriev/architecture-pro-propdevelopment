#!/bin/bash

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/logs/audit.log"
POD="$(kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "${POD}" ]]; then
  echo "Не найден pod kube-apiserver в kube-system" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUT")"
# В логе могут быть префиксы kube; ищем JSON аудита по полям Event/auditID
kubectl logs -n kube-system "$POD" --tail=20000 \
  | grep -E '"kind":"Event"|"auditID"' \
  > "$OUT" || true
echo "Записано в $OUT (строк: $(wc -l < "$OUT"))"
