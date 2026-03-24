# Task7: аудит небезопасных Pod-конфигураций

## Что сделано

- Создан namespace "audit-zone" с уровнем PodSecurity "restricted".
- Подготовлены 3 небезопасных манифеста в "insecure-manifests/":
  - 01-privileged-pod.yaml (privileged: true)
  - 02-hostpath-pod.yaml (hostPath)
  - 03-root-user-pod.yaml (runAsUser: 0)
- Подготовлены исправленные версии в "secure-manifests/" с безопасным securityContext.
- Добавлены ConstraintTemplate и Constraint для OPA Gatekeeper:
  - запрет "privileged: true"
  - запрет "hostPath`
  - обязательные "runAsNonRoot: true" и "readOnlyRootFilesystem: true"
- Добавлены скрипты проверки:
  - verify/verify-admission.sh
  - verify/validate-security.sh
- Добавлен пример конфигурации PodSecurity admission в audit-policy.yaml.



## Как проверить

### 1) Запуск minikube

```
minikube start
kubectl config use-context minikube
kubectl cluster-info
```

### 2) Запуск полной проверки

```
chmod +x verify/verify-admission.sh verify/validate-security.sh
./verify/verify-admission.sh
./verify/validate-security.sh
```

### 3) Что должно получиться

- Небезопасные манифесты отклоняются ("kubectl apply --dry-run=server" возвращает ошибку admission).
- Безопасные манифесты проходят валидацию.
- В "audit-zone" стоят метки:
  - pod-security.kubernetes.io/enforce=restricted
  - pod-security.kubernetes.io/audit=restricted
  - pod-security.kubernetes.io/warn=restricted
- В кластере присутствуют и активны Gatekeeper-constraints:
  - deny-privileged
  - deny-hostpath
  - enforce-runasnonroot-readonly
