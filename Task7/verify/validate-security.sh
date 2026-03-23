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

echo "== Dry-run checks =="
echo "-- insecure manifests (must FAIL) --"
for file in "${ROOT_DIR}"/insecure-manifests/*.yaml; do
  if kubectl apply --dry-run=server -f "$file" >/tmp/validate.out 2>&1; then
    echo "FAIL: ${file##*/} passed but must be rejected"
    exit 1
  fi
  echo "OK: ${file##*/} rejected"
done

echo "-- secure manifests (must PASS) --"
for file in "${ROOT_DIR}"/secure-manifests/*.yaml; do
  kubectl apply --dry-run=server -f "$file" >/dev/null
  echo "OK: ${file##*/} passed"
done

echo "Validation completed successfully."
