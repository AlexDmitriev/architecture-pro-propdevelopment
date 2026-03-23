# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - kubernetes-admin
   - Где: 192.168.49.2
   - secrets \"bootstrap-token-yyppb9\" not found", обращение к несуществующему токену

2. Привилегированные поды:
   - minikube-user
   - Попытка применить к поду комманду (sleep 3600)

3. Использование kubectl exec в чужом поде:
   - Использование exec не выявлено

4. Создание RoleBinding с правами cluster-admin:
   - kubernetes-admin
   - Назначение роли ClusterRole группе kubeadm:cluster-admins

5. Удаление audit-policy.yaml:
   - Попыток удаления audit-policy.yaml не выявлено
   - (тут, возможно надо подправить задание, т.к
   ```
   ➜  kube kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=root
   error: the path "/etc/kubernetes/audit-policy.yaml" does not exist
   ```
   попытка удаления из скрипта отваливается с ошибкой, возможно старая версия minikube) 


## Вывод

1) Осуществляется несанкционированный доступ к секретам, попытка угадать токен. 
2) Происходят попытка подготовить точку входа/эскалации через привилегированый под.
3) Попытка расширить привелегии группы, нет понимания, санкционированные или нет
