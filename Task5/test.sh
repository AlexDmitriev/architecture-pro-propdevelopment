#!/bin/bash

set -euo pipefail

ok() { echo "[OK] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

kubectl wait --for=condition=Ready pod/front-end-app --timeout=120s >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/back-end-api-app --timeout=120s >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/admin-front-end-app --timeout=120s >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/admin-back-end-api-app --timeout=120s >/dev/null 2>&1 || true

expect_allow() {
  local from_pod="$1"
  local to_svc="$2"
  local port="$3"

  local code
  code="$(kubectl exec "$from_pod" -- curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$to_svc:$port" || true)"
  [[ "$code" == "200" ]] || fail "$from_pod -> $to_svc:$port ожидался доступ, получили HTTP '$code'"
  ok "$from_pod -> $to_svc:$port разрешено (HTTP $code)"
}

expect_deny() {
  local from_pod="$1"
  local to_svc="$2"
  local port="$3"

  local code
  code="$(kubectl exec "$from_pod" -- curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$to_svc:$port" || true)"
  [[ "$code" != "200" ]] || fail "$from_pod -> $to_svc:$port НЕ ожидался доступ, но получили HTTP 200"
  ok "$from_pod -> $to_svc:$port запрещено (HTTP $code)"
}

echo "=== Допустимые пары (в обе стороны) ==="
expect_allow front-end-app back-end-api-app 80
expect_allow back-end-api-app front-end-app 80
expect_allow admin-front-end-app admin-back-end-api-app 80
expect_allow admin-back-end-api-app admin-front-end-app 80

echo "=== Недопустимые пары (в обе стороны) ==="
expect_deny front-end-app admin-front-end-app 80
expect_deny admin-front-end-app front-end-app 80

expect_deny front-end-app admin-back-end-api-app 80
expect_deny admin-back-end-api-app front-end-app 80

expect_deny back-end-api-app admin-front-end-app 80
expect_deny admin-front-end-app back-end-api-app 80

expect_deny back-end-api-app admin-back-end-api-app 80
expect_deny admin-back-end-api-app back-end-api-app 80