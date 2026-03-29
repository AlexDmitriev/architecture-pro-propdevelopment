#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check_cluster() {
  local context
  context="$(kubectl config current-context 2>/dev/null || true)"
  if ! kubectl version --request-timeout=5s >/dev/null 2>&1; then
    echo "Kubernetes API недоступен."
    echo "Текущий контекст: ${context:-<не задан>}"
    echo "Запустите кластер и выберите контекст, например:"
    echo "  minikube start"
    echo "  kubectl config use-context minikube"
    echo "  kubectl cluster-info"
    exit 1
  fi
}

check_tools() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Требуется python3 (проверка полей манифестов)."
    exit 1
  fi
}

# Проверка обязательных полей securityContext у каждого контейнера (явные значения).
verify_secure_pod_manifest_fields() {
  local file="$1"
  if ! python3 - "$file" <<'PY'
import json, subprocess, sys

path = sys.argv[1]
out = subprocess.check_output(
    [
        "kubectl",
        "create",
        "--dry-run=client",
        "--validate=false",
        "-o",
        "json",
        "-f",
        path,
    ],
    text=True,
)
obj = json.loads(out)
if obj.get("kind") != "Pod":
    print("FAIL: ожидался kind Pod", file=sys.stderr)
    sys.exit(1)
containers = obj.get("spec", {}).get("containers") or []
if not containers:
    print("FAIL: нет контейнеров", file=sys.stderr)
    sys.exit(1)
for i, c in enumerate(containers):
    sc = c.get("securityContext")
    if not isinstance(sc, dict):
        print(f"FAIL: контейнер {i}: нет securityContext", file=sys.stderr)
        sys.exit(1)
    def need(key, expected):
        if key not in sc:
            print(f"FAIL: контейнер {i}: нет явного поля {key}", file=sys.stderr)
            return False
        if sc[key] != expected:
            print(f"FAIL: контейнер {i}: {key}={sc[key]!r}, ожидалось {expected!r}", file=sys.stderr)
            return False
        return True
    if not (
        need("privileged", False)
        and need("runAsNonRoot", True)
        and need("readOnlyRootFilesystem", True)
    ):
        print(json.dumps(sc, indent=2, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
sys.exit(0)
PY
  then
    echo "FAIL: в ${file##*/} не выполнены требования к securityContext контейнеров:"
    echo "  privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: true (явно заданы)."
    return 1
  fi
}

cleanup_secure_pods() {
  kubectl delete -f "${ROOT_DIR}/secure-manifests/" --ignore-not-found --wait=false 2>/dev/null || true
}

check_tools
check_cluster

echo "== PodSecurity labels on namespace =="
kubectl get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}'
kubectl get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}{"\n"}'
kubectl get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}{"\n"}'

echo "== Gatekeeper webhook and pods =="
kubectl get validatingwebhookconfigurations -o name | grep gatekeeper
kubectl -n gatekeeper-system get pods

echo "== Constraints and violations counters =="
kubectl get constraints

echo "== Поля securityContext в secure-манифестах (privileged, runAsNonRoot, readOnlyRootFilesystem) =="
for file in "${ROOT_DIR}"/secure-manifests/*.yaml; do
  verify_secure_pod_manifest_fields "$file"
  echo "OK: ${file##*/} поля контейнера соответствуют"
done

echo "== Dry-run checks =="
echo "-- insecure manifests (must FAIL) --"
for file in "${ROOT_DIR}"/insecure-manifests/*.yaml; do
  if kubectl apply --dry-run=server -f "$file" >/tmp/validate.out 2>&1; then
    echo "FAIL: ${file##*/} passed but must be rejected"
    exit 1
  fi
  echo "OK: ${file##*/} rejected"
done

echo "-- secure manifests (must PASS server dry-run) --"
for file in "${ROOT_DIR}"/secure-manifests/*.yaml; do
  kubectl apply --dry-run=server -f "$file" >/dev/null
  echo "OK: ${file##*/} passed dry-run=server"
done

echo "== Запуск secure-подов в кластере (не только dry-run) =="
trap cleanup_secure_pods EXIT
cleanup_secure_pods
for file in "${ROOT_DIR}"/secure-manifests/*.yaml; do
  kubectl apply -f "$file"
  pod_name="$(kubectl create --dry-run=client --validate=false -o jsonpath='{.metadata.name}' -f "$file")"
  ns="$(kubectl create --dry-run=client --validate=false -o jsonpath='{.metadata.namespace}' -f "$file")"
  echo "  ожидание Ready: pod/${pod_name} namespace/${ns}"
  kubectl wait --for=condition=Ready "pod/${pod_name}" -n "${ns}" --timeout=180s
  echo "OK: ${file##*/} pod запущен и Ready"
done

echo "Validation completed successfully."
