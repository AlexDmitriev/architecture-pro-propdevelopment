#!/bin/bash

minikube stop
minikube delete --all

minikube config set memory 4096
minikube config set cpus 2
# audit-log-path=-: аудит в stdout apiserver (в minikube запись в /var/log часто не даёт файла на хосте).
minikube start --driver=docker  \
  --mount --mount-string="/home/alex/projects/study/architecture-pro-propdevelopment/Task6/logs:/var/log" \
  --addons=ingress --wait-timeout=10m \
  --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml \
  --extra-config=apiserver.audit-log-path=-
