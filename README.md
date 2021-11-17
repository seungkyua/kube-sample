### Documents

- https://kubernetes.io/docs/home/



## 생각해 보기

- sa, clusterrole, clusterrolebinding 만들기
  - sa 를 사용, deployments, statefulsets 가 create 만 가능
- pvc  만들기 (storageclass 연결), pvc 를 pod 와 연결, pvc size 변경 및 변경내용을 기록하기
- deployment scale out
- etcd 백업 및 restore (etcd snapeshot save, etcd snapshot restore)
- master upgrade (1.21.1 -> 1.22.0)
- node 문제 찾고 영구적으로 해결 (kubelet start and systemctl enable kubelet)
- 특정 pod label 에서 cpu 를 가장 많이 사용하는 pod 찾기 (kubectl top pod -l name=app)
- NetworkPolicy (특정 namespace 의 모든 pod 는 특정 namespace 의 pod 의 특정 port 만 허용)
- 기존 pod 에 sidecar container 를 추가하고 hostpath 에 로그 남기기
- ingress resource 만들기  (path /hello)



### bashrc 참고

```bash
$ cat ~/.bashrc

alias vi="vim"
alias kubectl="k3s kubectl"
source /etc/profile.d/bash_completion.sh
source <(kubectl completion bash)
alias k=kubectl
complete -F __start_kubectl k
eval "$(starship init bash)"
export PS1="\h $ "
```



```bash
$ cat ~/.bash_profile

# Colors
black="\[$(tput setaf 0)\]"
red="\[$(tput setaf 1)\]"
green="\[$(tput setaf 2)\]"
yellow="\[$(tput setaf 3)\]"
blue="\[$(tput setaf 4)\]"
magenta="\[$(tput setaf 5)\]"
cyan="\[$(tput setaf 6)\]"
white="\[$(tput setaf 7)\]"
# Title bar - "user@host: ~"
title="\u@\h: \w"
titlebar="\[\033]0;""\007\]"
# Git branch
git_branch() {   git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/(\1)\ /'; }
# Clear attributes
clear_attributes="\[$(tput sgr0)\]"

export PS1="${cyan}(admin${green}@${cyan}localhost) ${magenta}\W ${green}#${clear_attributes} "
```





### bash completion

```bash
$ sudo apt-get install bash-completion
$ source /usr/share/bash-completion/bash_completion
$ echo 'source <(kubectl completion bash)' >>~/.bashrc
$ sudo bash -c 'kubectl completion bash >/etc/bash_completion.d/kubectl'
$ source ~/.bashrc
```



### vimrc

```bash
$ sudo vi ~/.vimrc

set termguicolors
execute pathogen#infect()
syntax on
colorscheme dracula
filetype plugin indent on
:set paste

# add more
set tabstop=2
set expandtab
set shiftwidth=2
```



# Pod



### pod spec 보기

```bash
$ kubectl explain pod --recursive | less
$ kubectl explain pod --recursive | grep -A5 tolerations
```



### pod 생성

```bash
$ kubectl run nginx --image=nginx --labels=tier=db --port 80 --expose --restart=Never
$ kubectl run nginx --image=nginx --labels=tier=db --port 80 --expose --restart=Never --dry-run=client -o yaml > nginx-pod.yaml

$ kubectl run busybox --image=busybox --restart=Never --command sleep 1000
$ kubectl run busybox --image=busybox --restart=Never --command sleep 1000 --dry-run=client -o yaml > busybox-pod.yaml
```



### pod 강제 삭제

```bash
$ kubectl delete pod nginx --force --grace-period=0
```





# deployment



### deployment 생성

```bash
$ kubectl create deployment nginx --image=nginx --replicas=2
$ kubectl create deployment nginx --image=nginx --replicas=2 --dry-run=client -o yaml > nginx-deployment.yaml
```



### deployment 수정

```bash
$ kubectl scale deployment nginx --replicas=5
$ kubectl set image deployment nginx nginx=nginx:1.18
```



### namespace 지정

```bash
$ kubectl config set-context $(kubectl config current-context) --namespace=prod
```





# Service



### service 생성

```bash
# You should add the node port in manually
$ kubectl expose deployment simple-webapp-deployment --name=webapp-service --target-port=8080 --type=NodePort --port=8080 --dry-run=client -o yaml > webapp-svc.yaml
```





# Scheduling



### manual scheduling

```bash
$ nginx.yaml 

apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  -  image: nginx
     name: nginx
  nodeName: controlplan
```



### labels and selectors

```bash
$ kubectl get pods --show-labels

$ kubectl get pods -l env=dev --no-headers | wc -l
$ kubectl get pods --selector env=dev --no-headers | wc -l

$ kubectl get all -l env=prod --no-headers | wc -l
$ kubectl get all --selector env=prod --no-headers | wc -l

$ kubectl get all --selector env=prod,bu=finance,tier=frontend
```



### Taints and Tolerations

```bash
$ kubectl taint nodes node-name key=value:taint-effect
## taint-effect: NoSchedule | PreferNoSchedule | NoExecute
```



```bash
$ kubectl taint nodes node01 app=blue:NoSchedule

$ vi pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
  tolerations:
  - key: "app"
    operator: "Equal"
    value: "blue"
    effect: "NoSchedule"
```



```bash
$ kubectl taint nodes node01 spray=mortein:NoSchedule
```



### NodeSelectors

```
$ kubectl label node node01 size=Large

$ vi pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
  nodeSelector:
    size: Large
```





### Node Affinity

```bash
$ vi pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: size
            operator: In
            values:
            - Large
            - Medium
            

## operator: In | NotIn | Exsits .....
```



```bash
$ kubectl create deploy blue --image=nginx --replicas=3 --dry-run=client -o yaml > blue-deploy.yaml

$ vi blue-deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blue
  template:
    metadata:
      labels:
        app: blue
    spec:
      containers:
      - image: nginx
        name: nginx
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: color
                operator: In
                values:
                - blue
```



```bash
$ vi red-deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: red
spec:
  replicas: 2
  selector:
    matchLabels:
      app: red
  template:
    metadata:
      labels:
        app: red
    spec:
      containers:
      - image: nginx
        name: nginx
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role.kubernetes.io/master
                operator: Exists
```



### Resource Requests and Limits



**default LimitRange**

https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/memory-default-namespace/

https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/cpu-default-namespace/

```bash
---
apiVersion: v1
kind: LimitRange
metadata:
  name: mem-limit-range
spec:
  limits:
  - default:
      memory: 512Mi
    defaultRequest:
      memory: 256Mi
    type: Container

---
apiVersion: v1
kind: LimitRange
metadata:
  name: cpu-limit-range
spec:
  limits:
  - default:
      cpu: 1
    defaultRequest:
      cpu: 0.5
    type: Container


```



```bash
$ vi pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
    resources:
      requests:
        cpu: 1
        memory: "1Gi"
      limits:
        cpu: 2
        memory: "2Gi"
```





### DaemonSet

```bash
$ vi daemonset-definition.yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: elasticsearch
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - image: k8s.gcr.io/fluentd-elasticsearch:1.20
        name: fluentd-elasticsearch
```





### Multi Scheduler

```bash
$ vi my-scheduler.yaml 

apiVersion: v1
kind: Pod
metadata:
  labels:
    component: kube-scheduler
    tier: control-plane
  name: my-scheduler
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-scheduler
    - --authentication-kubeconfig=/etc/kubernetes/scheduler.conf
    - --authorization-kubeconfig=/etc/kubernetes/scheduler.conf
    - --bind-address=127.0.0.1
    - --kubeconfig=/etc/kubernetes/scheduler.conf
## check
    - --leader-elect=false
    - --port=10251
    - --scheduler-name=my-scheduler
    - --secure-port=0
##
    image: k8s.gcr.io/kube-scheduler:v1.20.0
    livenessProbe:
      failureThreshold: 8
      httpGet:
        host: 127.0.0.1
        path: /healthz
## check
        port: 10251
        scheme: HTTP
##
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 15
    name: my-scheduler
    resources:
      requests:
        cpu: 100m
    startupProbe:
      failureThreshold: 24
      httpGet:
        host: 127.0.0.1
        path: /healthz
## check
        port: 10251
        scheme: HTTP
##
```



```bash
$ vi nginx-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
  schedulerName: my-scheduler
```



```bash
## multi scheduler with leader elecation
apiVersion: v1
kind: Pod
metadata:
  labels:
    component: kube-scheduler
    tier: control-plane
  name: my-scheduler
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-scheduler
    - --authentication-kubeconfig=/etc/kubernetes/scheduler.conf
    - --authorization-kubeconfig=/etc/kubernetes/scheduler.conf
    - --bind-address=127.0.0.1
    - --kubeconfig=/etc/kubernetes/scheduler.conf
## check
    - --leader-elect=true
    - --scheduler-name=my-scheduler
    - --lock-object-name=my-scheduler
    - --port=10251
    - --secure-port=0
##
    image: k8s.gcr.io/kube-scheduler:v1.20.0
```





## Application Lifecycle Management



### Rollout

```bash
$ kubectl rollout status deploy myapp-deployment
$ kubectl rollout history deploy myapp-deployment
```



### Rollback

```bash
$ kubectl rollout undo deploy myapp-deployment
```



### Rolling Update

```bash
$ kubectl set image deploy frontend simple-webapp=kodekloud/webapp-color:v2
```

```
## replicas: 4
## maxUnavailable: 5%
## maxSurge: 5%

maxUnavailable 값이 5% 이면 4 * 0.05 = 0.2 의 pod 수 만큼만 down 될 수 있다. 절대 값으로 버림하면 0의 개수 만큼만 unavailable 할 수 있으니 pod 개수 4 만큼은 항상 available 해야 한다.

maxSurge 값이 5% 이면 4 * 1.05 = 4.2 의 pod 수 만큼 생성되어야 한다. 절대값으로 올리면 5의 pod 수 만큼 생성할 수 있다.

즉, 1 개의 pod 가 생성되어 running pod 수가 5개가 되면, 그 때 1개의 pod 가 terminating 되어 running pod 수 4 개는 유지한다.
```



### Env - ConfigMap

```bash
$ kubectl create configmap webapp-config-map --from-literal=APP_COLOR=darkblue

apiVersion: v1
kind: Pod
metadata:
  name: webapp-color
spec:
  containers:
  - envFrom:
    - configMapRef:  
        name: webapp-config-map
    image: kodekloud/webapp-color
    name: webapp-color



apiVersion: v1
kind: Pod
metadata:
  name: webapp-color
spec:
  containers:
  - env:
    - name: APP_COLOR
      valueFrom:
        configMapKeyRef:
          name: webapp-config-map
          key: APP_COLOR
    image: kodekloud/webapp-color
    name: webapp-color
```



### Env-Secret

```bash
$ kubectl create secret generic db-secret --from-literal=DB_Host=sql01 --from-literal=DB_User=root --from-literal=DB_Password=password123


apiVersion: v1
kind: Pod
metadata:
  name: webapp-pod
spec:
  containers:
  - image: kodekloud/simple-webapp-mysql
    name: webapp
    envFrom:
    - secretRef:
        name: db-secret
```



### InitContainer

```bash
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
  labels:
    app: myapp
spec:
  containers:
  - name: myapp-container
    image: busybox:1.28
    command: ['sh', '-c', 'echo The app is running! && sleep 3600']
  initContainers:
  - name: init-myservice
    image: busybox:1.28
    command: ['sh', '-c', 'until nslookup myservice; do echo waiting for myservice; sleep 2; done;']
  - name: init-mydb
    image: busybox:1.28
    command: ['sh', '-c', 'until nslookup mydb; do echo waiting for mydb; sleep 2; done;']

```





## Cluster Maintenance



### drain, cordon

```bash
$ kubectl drain node01 --ignore-daemonsets
$ kubectl uncordon node01
```



### cluster upgrade

```bash
$ apt update
$ apt-cache madison kubeadm

$ kubectl version --short

$ kubeadm upgrade plan
COMPONENT   CURRENT       AVAILABLE
kubelet     2 x v1.19.0   v1.19.16

## 1. controlplane drain
$ kubectl drain controlplane --ignore-daemonsets

## 2. kubeadm upgrade
$ apt update
$ apt install kubeadm=1.20.0-00

## 3. controlplane upgrade
$ kubeadm upgrade apply v1.20.0

## 4. kubelet upgrade
$ apt install kubelet=1.20.0-00
$ systemctl restart kubelet
$ kubectl uncordon controlplane

## 5. node drain
$ kubectl drain node01 --ignore-daemonsets --force

## 6. [node] kubeadm upgrade
$ apt update
$ apt install kubeadm=1.20.0-00
$ kubeadm upgrade node

## 7. [node] kubelet upgrade
$ apt install kubelet=1.20.0-00
$ systemctl restart kubelet

## 8. uncordon node
$ kubectl uncordon node01
```



### backup and restore

```bash
## API Server stop

$ ETCDCTL_API=3 etcdctl snapshot save /opt/snapshot-pre-boot.db \
--endpoints=https://127.0.0.1:2379 \
--cacert=/etc/kubernetes/pki/etcd/ca.crt \
--cert=/etc/kubernetes/pki/etcd/server.crt \
--key=/etc/kubernetes/pki/etcd/server.key

$ ETCDCTL_API=3 etcdctl snapshot status /opt/snapshot-pre-boot.db
$ ETCDCTL_API=3 etcdctl snapshot restore /opt/snapshot-pre-boot.db --data-dir /var/lib/etcd-from-backup

## etcd data-dir 수정
$ vi /etc/kuberentes/manifests/etcd.yaml
volumes:
  - hostPath:
      path: /var/lib/etcd-from-backup
      type: DirectoryOrCreate
    name: etcd-data

## API server start
```





## Security



### Password

```bash
$ vi /tmp/users/user-details.cvs
password123,user1,u0001

$ api-server.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
      <content-hidden>
    - --basic-auth-file=/tmp/users/user-details.csv
    volumeMounts:
    - mountPath: /tmp/users
      name: usr-details
      readOnly: true
  volumes:
  - hostPath:
      path: /tmp/users
      type: DirectoryOrCreate
    name: usr-details


$ role.yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
 
---
# This role binding allows "jane" to read pods in the "default" namespace.
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: user1 # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io



$ curl -v -k https://master-node-ip:6443/api/v1/pods -u "user1:password123"
```



### Token

```bash
$ vi /tmp/users/user-token-details.cvs
KpjCVbI7rCFA,user1,u0010,group1

$ vi api-server.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
      <content-hidden>
    - --token-auth-file=/tmp/users/user-details.csv
    volumeMounts:
    - mountPath: /tmp/users
      name: usr-details
      readOnly: true
  volumes:
  - hostPath:
      path: /tmp/users
      type: DirectoryOrCreate
    name: usr-details


$ role.yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
 
---
# This role binding allows "jane" to read pods in the "default" namespace.
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: user1 # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io


$ curl -v -k https://master-node-ip:6443/api/v1/pods --header "Authorization: Bearer KpjCVbI7rCFA"

```



### Kubernetes TLS

```bash
##=========================================================================
## ca.key, ca.crt
##=========================================================================
$ openssl genrsa -out ca.key 1024
ca.key

$ openssl req -new -key ca.key -subj "/CN=KUBERNETES-CA" -out ca.csr 
ca.csr

$ openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt
ca.crt

##=========================================================================
## admin.key, admin.crt (client)
##=========================================================================
$ openssl genrsa -out admin.key 2048
admin.key

## group 이 system:masters 면 admin user 의 권한을 갖음
$ openssl req -new -key admin.key -subj "/CN=kube-admin/O=system:masters" -out admin.csr
admin.csr

$ openssl x509 -req -in admin.csr -CAkey ca.key -CA ca.crt -out admin.crt
admin.crt


$ curl https://kube-apiserver:6443/api/v1/pods --key admin.key --cert admin.crt --cacert ca.crt

##=========================================================================
## api-server (Server)
##=========================================================================
$ openssl genrsa -out apiserver.key 2048
apiserver.key

$ openssl req -new -key apiserver.key -subj "/CN=kube-apiserver" -out apiserver.csr -config openssl.cnf
apiserver.csr

$ vi openssl.cnf
[req]
req_extensions = v3_req
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,
subjectAltName = @alt_names
[alt_names]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster.local
IP.1 = 10.96.0.1
IP.2 = 172.17.0.27

$ openssl x509 -req -in apiserver.csr -CAkey ca.key -CA ca.crt -out apiserver.crt
apiserver.crt


##=========================================================================
## cert 내용 보기
##=========================================================================
$ openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout
...
    Issuer: CN=kubernetes
    Validity
      Not Before: ...
      Not After : Feb 11 05:39:20 2020 GMT
    Subject: CN=kube-apiserver
...
      x509v3 Subject Alternative Name:
        DNS:master, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, IP Address:10.96.0.1, IP Address:172.17.0.27


##=========================================================================
## Service logs
##=========================================================================
$ journalctl -u etcd.service -l


```



### Certificate API

```bash
$ openssl genrsa -out jane.key 2048
jane.key

$ openssl req -new -key jane.key -subj "/cn=jane" -out jane.csr
jane.csr

$ cat jane.csr | base64
yyyyyyyyyyy

$ vi jane-csr.yaml
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: jane
spec:
  groups:
  - system:authenticated
  usages:
  - digital signature
  - key encipherment
  - server auth
  signerName: kubernetes.io/kube-apiserver-client
  request:
    yyyyyyyyy


$ kubectl get csr
$ kubectl certificate approve jane

$ kubectl get csr jane -o yaml
...
status:
  certificate:
    xxxxxxxxxx
    
$ echo "xxxxxxxx" | base64 -d

```



### Kubeconfig

```bash 
$ kubectl get pods \
--server kube-apiserver:6443 \
--client-key admin.key \
--client-certificate admin.crt \
--certificate-authority ca.crt

$ kubeconfig.yaml
apiVersion: v1
kind: Config
current-context: kubernetes-admin@kubernetes

clusters:
- name: kubernetes
  cluster:
    certificate-authority: /etc/kubernetes/pki/ca.crt
    certificate-authority-data: xxxxxxxxxxx    # embeded
    server: https://kube-apiserver:6443

contexts:
- name: kubernetes-admin@kubernetes
  context:
    cluster: kubernetes
    user: kubernetes-admin
    namespace: kube-system

users:
- name: kubernetes-admin
  user:
    client-certificate: /etc/kubernetes/admin.crt
    client-key: /etc/kubernetes/admin.key
    client-certificate-data: xxxxxxxxxxxxx   # embeded
    client-key-data: xxxxxxxxxxxxxxxx        # embeded



$ kubectl config view


```



### RBAC

```bash
$ kubectl auth can-i create deployments -n kube-system --as dev-user
yes

$ kubectl auth can-i delete nodes
no

$ kubectl api-resources

$ vi developer-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metatdata:
  name: developer
rules:
- apiGroups
  - ""
  resources:
  - pods
  resourceNames:
  - blue
  - orange
  verbs:
  - list
  - get
  - create
  - update
  - delete
- apiGroups:
  - apps
  - extensions
  resources:
  - deployments
  verbs:
  - create
  
$ vi devuser-developer-binding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metatdata:
  name: devuser-developer-binding
subjects:
- kind: User
  name: dev-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```





### ServiceAccount

```bash
$ curl https://kube-apiserver:6443/api -insecure --header "Authorization: Bearer eyJhbG..."

$ vi pod-definition.yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-kubernetes-dashboard
spec:
  containers:
  - name: my-kubernetes-dashboard
    image: my-kubernetes-dashboard
  automountServiceAccountToken: false
```



### Image Security

```bash
$ kubectl create secret docker-registry regcred \
--docker-server=private-registry.io \
--docker-username=registry-user \
--docker-password=registry-password \
--docker-email=registry-user@org.com

$ nginx-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: private-registry.io/apps/internal-app
  imagePullSecrets:
  - name: regcred

```



### Security Context

```bash
$ kubectl exec ubuntu-sleeper -- whoami

$ nginx-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: private-registry.io/apps/internal-app
    securityContext:
      runAsUser: 1000
      capabilities:
        add: ["MAC_ADMIN"]

```



### Network Policy

```bash
## from 아래의 '-' 를 붙히는 냐에 따라 or 혹은 and 로 바뀜 (지금은 podSelector 와 namespaceSelector 가 and 임)
$ vi network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-policy
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          name: api-pod
      namespaceSelector:
        matchLabels:
          name: prod
    - ipBlock:
        cidr: 192.168.5.10/32
    ports:
    - protocal: TCP
      port: 3306
  egress:
  - to:
    - ipBlock:
        cidr: 192.168.5.10/32
    ports:
    - protocal: TCP
      port: 3306
      
      
      
$ vi internal-policy.yaml 
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: internal-policy
  namespace: default
spec:
  egress:
  - to:
    - podSelector:
        matchLabels:
          name: payroll
    ports:
    - port: 8080
      protocol: TCP
  - to:
    - podSelector:
        matchLabels:
          name: mysql
    ports:
    - port: 3306
      protocol: TCP
  podSelector:
    matchLabels:
      name: internal
  policyTypes:
  - Egress
```





## Storage



### PersistentVolume

```bash
$ vi pv-definition.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-vol1
spec:
  accessModes:
  - ReadWriteOnce
  capacity:
    storage: 1Gi
  hostPath:
    path: /tmp/data
  persistentVolumeReclaimPolicy: Retain
```



### PersistentVolumeClaim

```bash
$ vi pvc-definition.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: myclaim
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 500Mi
```



### Using PVC in Pod

```bash
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
    - name: myfrontend
      image: nginx
      volumeMounts:
      - mountPath: "/var/www/html"
        name: mypd
  volumes:
    - name: mypd
      persistentVolumeClaim:
        claimName: myclaim


$ vi nginx-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: webapp
  namespace: default
spec:
  containers:
  - image: kodekloud/event-simulator
    imagePullPolicy: Always
    name: event-simulator
    volumeMounts:
    - mountPath: /log
      name: log-vol
  volumes:
  - name: log-vol
    hostPath:
      path: /var/log/webapp
```



### StorageClass

```bash
$ vi sc-definition.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: kubernetes.io/no-provisioner
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer


$ vi pvc-definition.yaml
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


$ pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - image: nginx:alpine
    name: nginx
    volumeMounts:
    - name: local
      mountPath: /var/www/html
  volumes:
  - name: local
    persistentVolumeClaim:
      claimName: local-pvc

```





## Networking



### routing

```bash
$ ip addr add 192.168.2.10/24 dev eth0
$ ip route add 192.168.1.0/24 via 192.168.2.1
$ ip route add default via 192.168.2.1

## 한대의 linux 서버에서 2개의 서로 다른 newtwork nic 으로 보낼려고 할 때
$ echo 1 > /proc/sys/net/ipv4/ip_forward
$ vi /etc/sysctl.conf
...
net.ipv4.ip_forward = 1
...
```



### DNS

```bash
$ cat /etc/resolv.conf
nameserver	192.168.1.100
nameserver	8.8.8.8
search			mycompany.com

## hosts 과 dns 중 순서를 정할 때
$ cat /etc/nsswitch.conf
...
hosts:		file dns
...

## DNS record 타입  (CNAME 은 name to name)
A   	 web-server				192.168.1.1
AAAA	 web-server				2001:0db8:85a3:0000:0000:8a2e:0370:7334
CNAME	 food.web-server		eat.web-server, hungry.web-server
```



### Network Namespace

```bash
$ ip netns add red
$ ip netns add blue

$ ip netns exec red {ip link}
$ ip -n red {link}

##---------------------------------------------------------------
## ip link 로 직접 연결
##---------------------------------------------------------------
$ ip link add veth-red type veth peer name veth-blue
$ ip link set veth-red netns red
$ ip link set veth-blue netns blue
$ ip -n red addr add 192.168.15.1 dev veth-red
$ ip -n blue addr add 192.168.15.2 dev veth-blue
$ ip -n red link set veth-red up
$ ip -n blue link set veth-blue up

##---------------------------------------------------------------
## linux bridge (virtual network switch) 로 연결
##---------------------------------------------------------------
## bridge 생성
$ ip link add v-net-0 type bridge
$ ip link set dev v-net-0 up

## veth peer 를 한개만 지우면 다 지워짐
$ ip -n red link del veth-red

## veth peer 생성
$ ip link add veth-red type veth peer name veth-red-br
$ ip link add veth-blue type veth peer name veth-blue-br

## namespace 와 bridge 에 세팅
$ ip link set veth-red netns red
$ ip link set veth-red-br master v-net-0
$ ip link set veth-blue netns blue
$ ip link set veth-blue-br master v-net-0

## namesapce veth 에 ip 세팅 및 up
$ ip -n red addr add 192.168.15.1 dev veth-red
$ ip -n blue addr add 192.168.15.2 dev veth-blue
$ ip -n red link set veth-red up
$ ip -n blue link set veth-blue up

## bridge 에 ip 세팅
$ ip addr add 192.168.15.5/24 dev v-net-0

## namespace 에서 다른 호스트 route 를 bridge 를 보게 세팅
$ ip netns exec blue {ip route add 192.168.10/24 via 192.168.15.5}

## host 에서 iptables 로 연결
$ iptables -t nat -A POSTROUTING -s 192.168.15.0/24 -j MASQUERADE

## namespace 에서 인터넷으로 나가는 routing 세팅
$ ip netns exec blue {ip route add default via 192.168.15.5}
```



### Kubernetes ports

- https://kubernetes.io/docs/setup/independent/install-kubeadm/#check-required-ports



### CNI

```bash
$ vi kubelet.service
  --cni-conf-dir=/etc/cni/net.d
  --cni-bin-dir=/opt/cni/bin
  
./net-script.sh add <container> <namespace>
```



### Weavenet install

```bash
$ ip a | grep eth0
inet 10.42.174.6/24 brd 10.42.174.255 scope global eth0

## node ip 대역을 피해서 설정
$ kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')&env.IPALLOC_RANGE=10.50.0.0/16"
```



### CoreDNS

```bash
$ kubectl get configmap -n kube-system
coredns

$ cat /etc/coredns/Corefile
.:53 {
		errors
  	health {
#    		lameduck 5s
    }
  	kubernetes cluster.local in-addr.arpa ip6.arpa {
  			pods insecure
  			upstream
  			fallthrough in-addr.arpa ip6.arpa
#  			ttl 30
  	}
  	prometheus :9153
  	proxy . /etc/resolv.conf
#  	forward . /etc/resolv.conf {
#    		max_concurrent 1000
#    }
  	cache 30
  	reload
#  	loadbalance
#  	loop
}
```



### Ingress Resource

```bash
## rule 1
$ vi Ingress-wear.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wear
spec:
  backend:
  	serviceName: wear-service
  	servicePort: 80

## rule 2
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
  name: ingress-wear-watch
spec:
  rules:
  - http:
      paths:
      - path: /wear
        pathType: Prefix
        backend:
  	      service:
  	        name: wear-service
  	        port:
  	          number: 80
      - path: /watch
        pathType: Prefix
        backend:
  	      service:
  	        name: watch-service
  	        port:
  	          number: 80


## rule 3
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wear-watch
spec:
  rules:
  - host: wear.my-online-store.com
    http:
      paths:
      - backend:
  	      service:
  	        name: wear-service
  	        port:
  	          number: 80
  - host: watch.my-online-store.com
    http:
      paths:
      - backend:
  	      service:
  	        name: watch-service
  	        port:
  	          number: 80




$ kubectl create ingress ingress-test --rule="wear.my-online-store.com/wear*=wear-service:80"

```



### Ingress rewrite

- https://kubernetes.github.io/ingress-nginx/examples/rewrite/

```bash
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
  namespace: critical-space
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /pay
        pathType: Prefix
        backend:
  	      service:
  	        name: pay-service
  	        port:
  	          number: 8282



apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$2
  name: rewrite
  namespace: default
spec:
  rules:
  - host: rewrite.bar.com
    http:
      paths:
      - path: /something(/|$)(.*)
        backend:
  	      service:
  	        name: http-svc
  	        port:
  	          number: 80
```



```bash
$ kubectl create ns ingress-space
$ kubectl create configmap nginx-configuration -n ingress-space
$ kubectl create serviceaccount ingress-serviceaccount -n ingress-space
```



## Kubeadm Install

```bash
$ cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

$ cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
$ sudo sysctl --system

$ sudo apt-get update
$ sudo apt-get install -y apt-transport-https ca-certificates curl
$ sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
$ echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list


$ sudo apt-get update
$ sudo apt-get install -y kubelet=1.21.0-00 kubeadm=1.21.0-00 kubectl=1.21.0-00
$ sudo apt-mark hold kubelet kubeadm kubectl

$ kubeadm init --pod-network-cidr 10.244.0.0/16 --apiserver-advertise-address 10.1.85.11 --apiserver-cert-extra-sans=controlplane

$ mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

## node 01 에서
$ kubeadm join 10.1.85.11:6443 --token j5fr2r.op49b746pf0l4ljg \
        --discovery-token-ca-cert-hash sha256:d3fed1eba898ca73a7a3e261889d142b6e6396809949f10714c8e9123e5618a3

## https://v1-18.docs.kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#network-plugin-requirements
$ sudo sysctl net.bridge.bridge-nf-call-iptables=1

## https://kubernetes.io/docs/concepts/cluster-administration/addons/
$ kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```





## Jsonpath

```bash
$ kubectl get nodes -o=jsonpath='{.items[*].metadata.name}'
$ kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.osImage}'
$ kubectl config view --kubeconfig=my-kube-config -o jsonpath='{.users[*].name}'
$ kubectl get pv --sort-by=.spec.capacity.storage
$ kubectl get pv --sort-by=.spec.capacity.storage -o=custom-columns=NAME:.metadata.name,CAPACITY:.spec.capacity.storage
$ kubectl config view --kubeconfig=my-kube-config -o jsonpath='{.contexts[?(@.context.user=="aws-user")].name}'
```

