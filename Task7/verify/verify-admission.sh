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

echo "[0/7] Check Kubernetes connection"
check_cluster

echo "[1/7] Create namespace with PodSecurity restricted labels"
kubectl apply -f "${ROOT_DIR}/01-create-namespace.yaml"

echo "[2/7] Install Gatekeeper (if not installed)"
if ! kubectl get namespace gatekeeper-system >/dev/null 2>&1; then
  kubectl apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml"
fi

echo "[3/7] Wait for Gatekeeper controllers"
kubectl -n gatekeeper-system rollout status deploy/gatekeeper-controller-manager --timeout=180s

echo "[4/7] Apply Gatekeeper templates and constraints"
kubectl apply -f "${ROOT_DIR}/gatekeeper/constraint-templates/"
echo "    Wait until Gatekeeper constraint CRDs are ready"
applied=false
for _ in {1..24}; do
  if kubectl apply -f "${ROOT_DIR}/gatekeeper/constraints/" >/tmp/gatekeeper-constraints.out 2>&1; then
    applied=true
    break
  fi
  sleep 5
done

if [[ "${applied}" != "true" ]]; then
  echo "ERROR: failed to apply Gatekeeper constraints after waiting."
  cat /tmp/gatekeeper-constraints.out
  exit 1
fi

echo "[5/7] Verify insecure manifests are rejected"
for file in "${ROOT_DIR}"/insecure-manifests/*.yaml; do
  echo "  - checking ${file##*/}"
  if kubectl apply --dry-run=server -f "$file" >/tmp/insecure.out 2>&1; then
    echo "ERROR: ${file##*/} unexpectedly passed validation"
    cat /tmp/insecure.out
    exit 1
  else
    echo "OK: rejected as expected"
  fi
done

echo "[6/7] Verify secure manifests pass"
for file in "${ROOT_DIR}"/secure-manifests/*.yaml; do
  echo "  - checking ${file##*/}"
  kubectl apply --dry-run=server -f "$file"
done

echo "[7/7] Final policy checks"
kubectl get ns audit-zone --show-labels | sed -n '1,2p'
kubectl get constraints

echo "All checks passed."
