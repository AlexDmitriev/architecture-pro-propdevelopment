# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
 - Кто: system:serviceaccount:secure-ops:monitoring
 - Где: namespace kube-system
 - Почему подозрительно: сервисный аккаунт из secure-ops пытался получить доступ к secrets в системном namespace kube-system; запрос завершился 403 Forbidden

2. Привилегированные поды:
 - Кто: minikube-user
 - Комментарий: был создан pod privileged-pod в namespace secure-ops с securityContext.privileged: true, что даёт контейнеру повышенные привилегии на узле

3. Использование kubectl exec в чужом поде:
 - Кто: minikube-user
 - Что делал: выполнил cat /etc/resolv.conf через kubectl exec в pod coredns-7d764666f9-brt5h в namespace kube-system

4. Создание RoleBinding с правами cluster-admin:
 - Кто: minikube-user
 - К чему привело: создан RoleBinding escalate-binding в namespace secure-ops, который привязывает service account monitoring к ClusterRole cluster-admin, то есть фактически повышает его права до административных

5. Удаление audit-policy.yaml:
- Команда kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=admin завершается ошибкой resource mapping not found, потому что audit.k8s.io/v1, kind=Policy не является API-ресурсом Kubernetes. Это конфигурационный файл для kube-apiserver, а не объект, управляемый через Kubernetes API. Поэтому операция не приводит к появлению корректного события удаления в audit log.


## Вывод

В журнале аудита зафиксированы признаки попытки повышения привилегий и доступа к критичным ресурсам кластера. Наиболее опасными событиями являются создание привилегированного pod и выдача service account monitoring прав cluster-admin, так как они создают возможность полного контроля над кластером. Дополнительно попытка доступа к secrets в kube-system и выполнение kubectl exec в системном pod указывают на разведку и попытку получить чувствительную информацию внутри кластера.
