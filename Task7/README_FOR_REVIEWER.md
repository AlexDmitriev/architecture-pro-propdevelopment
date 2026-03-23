# Task7: аудит небезопасных Pod-конфигураций

## Что сделано

- Создан `namespace` `audit-zone` с уровнем PodSecurity `restricted` (`enforce`, `audit`, `warn`).
- Подготовлены 3 небезопасных манифеста в `insecure-manifests/`:
  - `01-privileged-pod.yaml` (`privileged: true`)
  - `02-hostpath-pod.yaml` (`hostPath`)
  - `03-root-user-pod.yaml` (`runAsUser: 0`)
- Подготовлены исправленные версии в `secure-manifests/` с безопасным `securityContext`.
- Добавлены ConstraintTemplate и Constraint для OPA Gatekeeper:
  - запрет `privileged: true`
  - запрет `hostPath`
  - обязательные `runAsNonRoot: true` и `readOnlyRootFilesystem: true`
- Добавлены скрипты проверки:
  - `verify/verify-admission.sh`
  - `verify/validate-security.sh`
- Добавлен пример конфигурации PodSecurity admission в `audit-policy.yaml`.

## Структура

```text
Task7/
├── 01-create-namespace.yaml
├── insecure-manifests/
│   ├── 01-privileged-pod.yaml
│   ├── 02-hostpath-pod.yaml
│   └── 03-root-user-pod.yaml
├── secure-manifests/
│   ├── 01-secure.yaml
│   ├── 02-secure.yaml
│   └── 03-secure.yaml
├── gatekeeper/
│   ├── constraint-templates/
│   │   ├── privileged.yaml
│   │   ├── hostpath.yaml
│   │   └── runasnonroot.yaml
│   └── constraints/
│       ├── privileged.yaml
│       ├── hostpath.yaml
│       └── runasnonroot.yaml
├── verify/
│   ├── verify-admission.sh
│   └── validate-security.sh
├── audit-policy.yaml
└── README_FOR_REVIEWER.md
```

## Как проверить

### 1) Предусловия

- Есть доступ к Kubernetes-кластеру (`kubectl config current-context` корректен).
- В кластере работает PodSecurity Admission (для современных версий Kubernetes это штатный механизм).

Если локальный кластер еще не запущен, поднимите Minikube:

```bash
minikube start
kubectl config use-context minikube
kubectl cluster-info
```

### 2) Запуск полной проверки

Из каталога `Task7`:

```bash
chmod +x verify/verify-admission.sh verify/validate-security.sh
./verify/verify-admission.sh
./verify/validate-security.sh
```

### 3) Что должно получиться

- Небезопасные манифесты отклоняются (`kubectl apply --dry-run=server` возвращает ошибку admission).
- Безопасные манифесты проходят валидацию.
- В `audit-zone` стоят метки:
  - `pod-security.kubernetes.io/enforce=restricted`
  - `pod-security.kubernetes.io/audit=restricted`
  - `pod-security.kubernetes.io/warn=restricted`
- В кластере присутствуют и активны Gatekeeper-constraints:
  - `deny-privileged`
  - `deny-hostpath`
  - `enforce-runasnonroot-readonly`

### 4) Ручные точечные проверки

```bash
kubectl apply -f 01-create-namespace.yaml
kubectl apply -f gatekeeper/constraint-templates/
for i in {1..24}; do kubectl apply -f gatekeeper/constraints/ && break || sleep 5; done

kubectl apply --dry-run=server -f insecure-manifests/01-privileged-pod.yaml
kubectl apply --dry-run=server -f insecure-manifests/02-hostpath-pod.yaml
kubectl apply --dry-run=server -f insecure-manifests/03-root-user-pod.yaml

kubectl apply --dry-run=server -f secure-manifests/01-secure.yaml
kubectl apply --dry-run=server -f secure-manifests/02-secure.yaml
kubectl apply --dry-run=server -f secure-manifests/03-secure.yaml
```

Ожидание: первые 3 команды для `insecure-manifests` завершаются ошибками admission, последние 3 для `secure-manifests` проходят.
