## Documents

- https://kubernetes.io/docs/home/



### kubectl Cheat Sheet

- https://kubernetes.io/docs/reference/kubectl/cheatsheet/



### kubectl proxy

```bash
kubectl proxy --port=8888 --address=0.0.0.0 --accept-hosts=^.*$ --kubeconfig /root/.kube/config
```



### Env - ConfigMap

검색어: configure a pod to use a configmap

```bash
$ kubectl create cm webapp-config-map --from-literal=APP_COLOR=darkblue


## ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: special-config
  namespace: default
data:
  SPECIAL_LEVEL: very
  SPECIAL_TYPE: charm

## Pod
apiVersion: v1
kind: Pod
metadata:
  name: dapi-test-pod
spec:
  containers:
    - name: test-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "env" ]
      envFrom:
      - configMapRef:
          name: special-config


## ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: env-config
  namespace: default
data:
  log_level: INFO

## Pod
apiVersion: v1
kind: Pod
metadata:
  name: dapi-test-pod
spec:
  containers:
    - name: test-container
      image: k8s.gcr.io/busybox
      command: [ "/bin/sh", "-c", "env" ]
      env:
        - name: LOG_LEVEL
          valueFrom:
            configMapKeyRef:
              name: env-config
              key: log_level


```



### Env - Secret

검색어: Using Secrets as environment variables

```bash
$ kubectl create secret generic mysecret --from-literal=username=user


## Secret
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm


## Pod
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
  - name: mycontainer
    image: redis
    env:
      - name: SECRET_USERNAME
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: username


## Pod
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
  - name: mycontainer
    image: redis
    envFrom:
    - secretRef:
        name: mysecret

```



### Pod Security

검색어: configure a pod security

```bash

apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-sleeper
spec:
  containers:
  - command:
    - sleep
    - "4800"
    image: ubuntu
    name: ubuntu
    securityContext:
      runAsUser: 1
      capabilities:
        add:
        - SYS_TIME
        - NET_ADMIN
```



### ServiceAccount

검색어: configure a pod with serviceaccount

```bash
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: build-robot
```



### Resource - cpu and memory

검색어: assign resources

```bash

apiVersion: v1
kind: Pod
metadata:
  name: cpu-demo
  namespace: cpu-example
spec:
  containers:
  - name: cpu-demo-ctr
    image: vish/stress
    resources:
      limits:
        cpu: "1"
      requests:
        cpu: "0.5"
    args:
    - -cpus
    - "2"
```







### Taint and Toleration

검색어: taint

```bash
$ kubectl taint nodes node01 spray=mortein:NoSchedule


apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: bee
  name: bee
spec:
  containers:
  - image: nginx
    name: bee
  tolerations:
  - key: spray
    operator: Equal
    value: mortein
    effect: NoSchedule

```



### NodeAffinity

검색어: nodeAffinity

```bash

apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: disktype
            operator: In
            values:
            - ssd            
  containers:
  - name: nginx
    image: nginx


```



### sidecar pod

```bash
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - image: kodekloud/event-simulator
    name: app
    volumeMounts:
    - name: log-volume
      mountPath: /log
  - name: sidecar
    image: kodekloud/filebeat-configured
    volumeMounts:
    - name: log-volume
      mountPath: /var/log/event-simulator
  volumes:
    - name: log-volume
      hostPath:
        path: /var/log/webapp
        type: DirectoryOrCreate
```



### Readiness and Liveness Probe

검색어: configure a readinessProbe

```bash
##---------------------------------------------------
## readinessProbe
##---------------------------------------------------

## http
    readinessProbe:
      httpGet:
        path: /healthz
        port: 8080
        httpHeaders:
        - name: Accept
          value: application/json
      initialDelaySeconds: 5
      periodSeconds: 5
      failureThreshold: 1

## exec
    readinessProbe:
      exec:
        command:
        - cat
        - /tmp/healthy
      initialDelaySeconds: 5
      periodSeconds: 5
      failureThreshold: 1

## tcp
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
      failureThreshold: 1

##---------------------------------------------------
## livenessProbe
##---------------------------------------------------

## http
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
        httpHeaders:
        - name: Accept
          value: application/json
      initialDelaySeconds: 3
      periodSeconds: 60
      failureThreshold: 1
  
```



### Monitoring

```bash
$ kubectl top node --sort-by=memory
$ kubectl top node --sort-by=cpu

$ kubectl top pod --sort-by=cpu --no-headers | tail -1
```



### Rollout

검색어: rollout

```bash
$ kubectl create deployment nginx --image=nginx:1.16
$ kubectl set image deployment nginx nginx=nginx:1.17 --record
$ kubectl edit deployments nginx --record

$ kubectl rollout history deployment nginx
REVISION CHANGE-CAUSE
1     <none>
2     kubectl set image deployment nginx nginx=nginx:1.17 --record=true
3     kubectl edit deployments. nginx --record=true


$ kubectl rollout history deployment nginx --revision=3
deployment.extensions/nginx with revision #3
 
Pod Template: Labels:    app=nginx
    pod-template-hash=df6487dc Annotations: kubernetes.io/change-cause: kubectl edit deployments. nginx --record=true
 
 Containers:
  nginx:
  Image:   nginx:latest
  Port:    <none>
  Host Port: <none>
  Environment:    <none>
  Mounts:   <none>
 Volumes:   <none>


$ kubectl rollout undo deployment nginx

$ kubectl rollout history deployment nginx
deployment.extensions/nginxREVISION CHANGE-CAUSE
1     <none>
3     kubectl edit deployments. nginx --record=true
4     kubectl set image deployment nginx nginx=nginx:1.17 --record=true



kubectl rollout undo deployment nginx --to-revision=1
```



### Job and CronJob

검색어: configure a job

```bash
$ kubectl create job my-job --image=busybox --dry-run=client -o yaml > job.yaml


## Job
apiVersion: batch/v1
kind: job
metadata:
  name: pi
spec:
  backoffLimit: 6
  completions: 3
  parallelism: 3
  template:
    spec:
      containers:
      - name: pi
        image: perl
        command: ["perl", "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never


$ kubectl create cronjob throw-dice-cron-job --image kodekloud/throw-dice --schedule='30 21 * * *' --dry-run=client -o yaml > cronjob.yaml

## CronJob
apiVersion: batch/v1
kind: CronJob
metadata:
  name: pi
spec:
  schedule: "*/1 * * * *"
  JobTemplate:
    spec:
      backoffLimit: 6
      completions: 3
      parallelism: 3
      template:
        spec:
          containers:
          - name: pi
            image: perl
            command: ["perl", "-Mbignum=bpi", "-wle", "print bpi(2000)"]
          restartPolicy: Never
```

| Entry                  | Description                                                | Equivalent to |
| ---------------------- | ---------------------------------------------------------- | ------------- |
| @yearly (or @annually) | Run once a year at midnight of 1 January                   | 0 0 1 1 *     |
| @monthly               | Run once a month at midnight of the first day of the month | 0 0 1 * *     |
| @weekly                | Run once a week at midnight on Sunday morning              | 0 0 * * 0     |
| @daily (or @midnight)  | Run once a day at midnight                                 | 0 0 * * *     |
| @hourly                | Run once an hour at the beginning of the hour              | 0 * * * *     |



### Ingress resource

검색어: configure a ingress resource

https://kubernetes.github.io/ingress-nginx/examples/

```bash
$ kubectl create ingress ingress-wear-watch \
-n app-space \
--rule="/wear=wear-service:8080" \
--rule="/stream=video-service:8080" \
--rule="/eat=food-service:8080" \
--annotation nginx.ingress.kubernetes.io/rewrite-target=/ \
--annotation nginx.ingress.kubernetes.io/ssl-redirect=false \
--dry-run=client -o yaml > ing.yaml


apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wear-watch
  namespace: app-space
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  rules:
  - http:
      paths:
      - backend:
          service:
            name: wear-service
            port:
              number: 8080
        path: /wear
        pathType: Prefix
      - backend:
          service:
            name: video-service
            port:
              number: 8080
        path: /stream
        pathType: Prefix
      - backend:
          service:
            name: food-service
            port:
              number: 8080
        path: /eat
        pathType: Prefix


```



### Role and RoleBinding

검색어: configure a role

```bash
$ kubectl create role ingress-role \
-n ingress-space \
--verb=get,update \
--resource=configmap \
--dry-run=client -o yaml > ingress-role.yaml
```



검색어: configure a rolebinding

```bash
$ kubectl create rolebinding ingress-role-binding \
-n ingress-space \
--role=ingress-role \
--serviceaccount=ingress-space:ingress-serviceaccount \
--dry-run=client -o yaml > ingress-role-binding.yaml
```



### NetworkPolicy

검색어: configure a network policy

```bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
```



### PersistentVolume and PesistentVolumeClaim

검색어: configure a pod to use persistent volume

```bash
## Pod with hostPath without PVC
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: webapp
  name: webapp
spec:
  containers:
  - image: kodekloud/event-simulator
    name: webapp
    volumeMounts:
    - name: log-volume
      mountPath: /log
  volumes:
  - name: log-volume
    hostPath:
      path: /var/log/webapp
      type: DirectoryOrCreate



## PV with hostPath
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-log
spec:
  capacity:
    storage: 100Mi
  accessModes:
  - ReadWriteMany
  hostPath:
    path: /pv/log
  persistentVolumeReclaimPolicy: Retain


## PVC
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: claim-log-1
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 50Mi


## Pod with PVC
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: webapp
  name: webapp
spec:
  containers:
  - image: kodekloud/event-simulator
    name: webapp
    volumeMounts:
    - name: log-volume
      mountPath: /log
  volumes:
  - name: log-volume
    persistentVolumeClaim:
      claimName: claim-log-1

```



### StorageClass

검색어: configure a storage class

```bash
## PVC with StorageClass
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: local-pvc
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 500Mi
  storageClassName: local-storage


## Pod with PVC
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - image: nginx:alpine
    name: nginx
    volumeMounts:
    - name: www
      mountPath: /var/www/html
  volumes:
  - name: www
    persistentVolumeClaim:
      claimName: local-pvc


## StroageClass
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: delayed-volume-sc
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer

```



### StatefulSet

검색어: configure a statefulset

```bash
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  ports:
  - port: 80
    name: web
  clusterIP: None
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  serviceName: "nginx"
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
```



### Authentication and Authorization

검색어: api access control

```bash
## Basic auth file
--base-auth-file=user-details.csv
$ curl -v -k https://kube-apiserver:6443/api/v1/pods -u 'user1:password123'

## token auth file
--token-auth-file=user-details.csv
$ curl -v -k https://kube-apiserver:6443/api/v1/pods -H 'Authorization: Bearer xxxxxxxxx'
```



### Kubeconfig

검색어: configure access to multi cluster

```bash
$ kubectl config set users.dev-user.client-certificate /etc/kubernetes/pki/users/dev-user/dev-user.crt
```



### Authorization Mode and RBAC

검색어: authorization

검색어: using RBAC authorization

```bash
## kube-apiserver arguments 
--authorization-mode=Node,RBAC,Webhook

$ kubectl auth can-i create deployments --as dev-user -n default

## Deployments API Groups: "apps", "extensions"
```



### Admission Controller

검색어: using admission controller

```bash
## kube-apiserver arguments
--enable-admission-plugins=NamespaceLifecycle,LimitRanger ...
--disable-admission-plugins=PodNodeSelector,AlwaysDeny ...
```



### Mutating and Validating Admission Controller

검색어: dynamic admission controller

```bash
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: demo-webhook
webhooks:
- name: webhook-server.webhook-demo.svc
  clientConfig:
    service:
      name: webhook-server
      namespace: webhook-demo
      path: "/mutate"
    caBundle: LS0tLS1CRUdJTiB...
  rules:
  - apiGroups:   [""]
    apiVersions: ["v1"]
    operations:  ["CREATE"]
    resources:   ["pods"]
    scope:       "Namespaced"
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  timeoutSeconds: 5
```



### API version

검색어: install kubectl convert plugin

검색어: deprecated api migration guide

검색어: kube-apiserver

```bash
## kubectl-convert download
$ curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl-convert

## install kubectl-convert
$ sudo install -o root -g root -m 0755 kubectl-convert /usr/local/bin/kubectl-convert

## convert yaml
$ kubectl-convert -f nginx.yaml --output-version apps/v1


## find preferred version for authorization.k8s.io
$ kubectl proxy 8001 &
$ curl localhost:8001/apis/authorization.k8s.io

## group rbac.authorization.k8s.io 의 v1alpha1 버전 api enable in kube-apiserver
--runtime-config=rbac.authorization.k8s.io/v1alpha1

```

