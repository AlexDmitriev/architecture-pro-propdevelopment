#!/bin/bash

set -euo pipefail

minikube delete
minikube start --driver=docker --cni=calico

until kubectl get --raw='/healthz' >/dev/null 2>&1; do sleep 1; done
kubectl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null
until [[ "$(kubectl get ns default -o jsonpath='{.status.phase}' 2>/dev/null || true)" == "Active" ]]; do sleep 1; done
until kubectl get sa default -n default >/dev/null 2>&1; do sleep 1; done

kubectl -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=180s >/dev/null 2>&1 || true
kubectl -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-kube-controllers --timeout=180s >/dev/null 2>&1 || true

kubectl run front-end-app --image=nginx --labels role=front-end --expose --port 80 
kubectl run back-end-api-app --image=nginx --labels role=back-end-api --expose --port 80
kubectl run admin-front-end-app --image=nginx --labels role=admin-front-end --expose --port 80
kubectl run admin-back-end-api-app --image=nginx --labels role=admin-back-end-api --expose --port 80

kubectl apply -f non-admin-api-allow.yaml

kubectl wait --for=condition=Ready pod/front-end-app --timeout=120s >/dev/null
kubectl wait --for=condition=Ready pod/back-end-api-app --timeout=120s >/dev/null
kubectl wait --for=condition=Ready pod/admin-front-end-app --timeout=120s >/dev/null
kubectl wait --for=condition=Ready pod/admin-back-end-api-app --timeout=120s >/dev/null