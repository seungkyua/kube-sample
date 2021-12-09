https://itnext.io/cks-exam-series-1-create-cluster-security-best-practices-50e35aaa67ae



### capabilities

```bash
$ sudo apt-get update && sudo apt-get install -y libcap2-bin

$ capsh --print
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
```





# 1. Cluster Hardening



### Encrypted etcd

검색어: encrypted data

```bash
##------------------------------------------------------
## apiserver 에 encryption 적용
##------------------------------------------------------
$ mkdir -p /etc/kubernetes/etcd/

$ echo -n passwordpassword | base64
cGFzc3dvcmRwYXNzd29yZA==

$ vi /etc/kubernetes/etcd/ec.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: cGFzc3dvcmRwYXNzd29yZA==
    - identity: {}


$ vi /etc/kubernetes/manifests/kube-apiserver.yaml
...
    - --encryption-provider-config=/etc/kubernetes/etcd/ec.yaml
...
    volumeMounts:
...
    - mountPath: /etc/kubernetes/etcd
      name: etcd
      readOnly: true
  volumes:
...
  - hostPath:
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate
    name: etcd


$ sudo tail -f /var/log/pods/kube-system_kube-apiserver-ahnsk-deploy_1d3a4f5d7397f1ee1728b0996a9156bc/kube-apiserver/0.log



##------------------------------------------------------
## 암호화를 enable 시키고 secret 을 다 암호화 하고 싶을 때
##------------------------------------------------------
$ kubectl get secrets -A -o json | kubectl replace -f -

```





### Auditing

```bash
##----------------------------------------
## audit-policy.yaml
##----------------------------------------
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]
  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]
  # Log all other resources in core and extensions at the Request level.
  - level: Request
    resources:
    - group: "" # core API group
    - group: "extensions" # Version of group should NOT be included.
  ## Log all Metadata level
  - level: Metadata


##----------------------------------------
## kube-apiserver.yaml
##----------------------------------------

- --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
- --audit-log-path=/var/log/kubernetes/audit/audit.log \
- --audit-log-maxage=30 \
- --audit-log-maxbackup=5

...
  volumeMounts:
  - mountPath: /etc/kubernetes/audit-policy.yaml
    name: audit
    readOnly: true
  - mountPath: /var/log/kubernetes/audit/
    name: audit-log
    readOnly: false
...
volumes:
- name: audit
	hostPath:
		path: /etc/kubernetes/audit-policy.yaml
		type: File

- name: audit-log
	hostPath:
		path: /var/log/kubernetes/audit/
		type: DirectoryOrCreate

```







### Create User

```bash
##----------------------------------------
## Certificate Signing Requests
##----------------------------------------
$ openssl genrsa -out john.key 2048
$ openssl req -new -key john.key -subj "/CN=john/O=developers" -out john.csr

$ cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: john
spec:
  groups:
  - system:authenticated
  request: $(cat john.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

$ kubectl get csr
NAME   AGE   SIGNERNAME                            REQUESTOR          CONDITION
john   45s   kubernetes.io/kube-apiserver-client   kubernetes-admin   Pending

$ kubectl certificate approve john

$ kubectl get csr john -o jsonpath='{.status.certificate}' | base64 -d > john.crt

$ useradd -m john -s /bin/bash
$ cp john.crt john.key /home/john/
$ cp /etc/kubernetes/pki/ca.crt /home/john/
$ chown john.john -R /home/john


##----------------------------------------
## john 의 kubeconfig 만들기
## 검색어: configure access to multiple cluster
##----------------------------------------
$ su - john
$ export SERVER_IP=192.168.30.13
$ kubectl config set-cluster kubernetes \
--server=https://${SERVER_IP}:6443 \
--certificate-authority=/home/john/ca.crt \
--embed-certs \
--kubeconfig=john.kubeconfig

$ kubectl config set-credentials john \
--client-certificate=/home/john/john.crt \
--client-key=/home/john/john.key \
--embed-certs \
--kubeconfig=john.kubeconfig

$ kubectl config set-context default \
--cluster=kubernetes \
--user=john \
--kubeconfig=john.kubeconfig

$ kubectl config use-context default --kubeconfig=john.kubeconfig
$ cp john.kubeconfig ~/.kube/config

```



### RBAC

```bash
$ kubectl proxy --port 8025 &
$ curl localhost:8025/api/v1 | less
$ ps -ef|grep kubectl
$ kill -9 22362



apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list", "create"]
  

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-rolebinding
  namespace: default
subjects:
- kind: User
  name: john
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader-role
  apiGroup: rbac.authorization.k8s.io
  
  
$ su - john
$ kubectl auth can-i create pods
```









# 2. Minimize Microservice Vulnerabilities



### PodSecurityPolicy

```bash
##----------------------------------------
## privileged-psp 생성
##----------------------------------------
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged-psp
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

##----------------------------------------
## clusterrole 생성
##----------------------------------------
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: privileged-clusterrole
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - privileged-psp

##----------------------------------------
## clusterrolebinding 생성
##----------------------------------------
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: privileged-clusterrolebidning
roleRef:
  kind: ClusterRole
  name: privileged-clusterrole
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: system:authenticated

##----------------------------------------
## admision controller 에 추가
##----------------------------------------
kube-apiserver.yaml
...
--enable-admission-plugins=NodeRestriction,PodSecurityPolicy


##----------------------------------------
## log 로 이상여부 확인
##----------------------------------------
$ journalctl -u kubelet -f


##----------------------------------------
## privileged pod 생성 -> 성공
##----------------------------------------
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: privileged-pod
  name: privileded-pod
spec:
  containers:
  - image: nginx
    name: privileged-pod
    securityContext:
      privileged: true






##----------------------------------------
## restrictive psp 생성 (privileged 만 false)
##----------------------------------------
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restrictive-psp
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: false
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  

##----------------------------------------
## clusterrole 생성
##----------------------------------------
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: restrictive-clusterrole
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - restrictive-psp
  
  
##----------------------------------------
## rolebinding 생성 (default 네임스페이스에 적용)
##----------------------------------------
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: restrictive-rolebidning
  namespace: default
roleRef:
  kind: ClusterRole
  name: restrictive-clusterrole
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: system:authenticated
  

##----------------------------------------
## privileged clusterrolebinding 삭제
## rolebinding 생성 (kube-system 네임스페이스에 적용)
##----------------------------------------
$ kubectl delete clusterrolebinding privileged-clusterrolebidning

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: privileged-rolebidning
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: privileged-clusterrole
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: system:authenticated


##----------------------------------------
## john user 로 privileged pod 생성 -> 실패
##----------------------------------------
$ su - john

apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    run: privileged-pod
  name: privileded-pod
spec:
  containers:
  - image: nginx
    name: privileged-pod
    securityContext:
      privileged: true


```





### ImagePolicyWebhook

https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook

```bash
##------------------------------------------------------
## kube-apiserver.yaml
##------------------------------------------------------

- --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
- --enable-admission-plugins=ImagePolicyWebhook

...
  volumeMounts:
  - mountPath: /etc/kubernetes/admission/admission_config.yaml
    name: image-policy
    readOnly: true
...
volumes:
- name: image-policy
	hostPath:
		path: /etc/kubernetes/admission/admission_config.yaml
		type: File


##------------------------------------------------------
## admission_config.yaml
##------------------------------------------------------
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/admission/kubeconfig.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: false
      

##------------------------------------------------------
## kubeconfig.yaml
##------------------------------------------------------
# clusters refers to the remote service.
clusters:
- name: name-of-remote-imagepolicy-service
  cluster:
    certificate-authority: /path/to/ca.pem    # CA for verifying the remote service.
    server: https://images.example.com/policy # URL of remote service to query. Must use 'https'.

# users refers to the API server's webhook configuration.
users:
- name: name-of-api-server
  user:
    client-certificate: /path/to/cert.pem # cert for the webhook admission controller to use
    client-key: /path/to/key.pem          # key matching the cert

```



### Ingress

```bash
$ kubectl create ingress insecure-ingress \
-n cks \
--rule="/service1=service1:80" \
--rule="/service2=service2:80" \
--annotation nginx.ingress.kubernetes.io/rewrite-target=/ \
--dry-run=client -o yaml > insecure-ingress.yaml


##----------------------------------------
## ingressClassName: nginx 추가
##----------------------------------------
$ cat secure-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
  name: insecure-ingress
  namespace: cks
spec:
  ingressClassName: nginx
  rules:
  - http:
      paths:
      - backend:
          service:
            name: service1
            port:
              number: 80
        path: /service1
        pathType: Exact
      - backend:
          service:
            name: service2
            port:
              number: 80
        path: /service2
        pathType: Exact



##----------------------------------------
## pod1, pod2 생성
##----------------------------------------
$ kubectl run pod1 -n cks --image nginx
$ kubectl run pod2 -n cks --image httpd


##----------------------------------------
## service1, service2 생성
##----------------------------------------
$ kubectl expose pod pod1 -n cks --name service1 --port 80
$ kubectl expose pod pod2 -n cks --name service2 --port 80


##----------------------------------------
## 호출
##----------------------------------------
$ curl 10.0.145.156:32080/service1
$ curl 10.0.145.156:32080/service2
```



```bash
##----------------------------------------
## https 호출
##----------------------------------------
$ curl -kv https://10.0.145.156:32443/service1
...
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: O=Acme Co; CN=Kubernetes Ingress Controller Fake Certificate
*  start date: Oct 24 16:34:32 2021 GMT
*  expire date: Oct 24 16:34:32 2022 GMT
*  issuer: O=Acme Co; CN=Kubernetes Ingress Controller Fake Certificate
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
...


##----------------------------------------
## key,cert 생성 (Common Name: secure-ingress.com)
##----------------------------------------
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
...
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:secure-ingress.com
Email Address []:


$ kubectl create secret tls secure-ingress-tls -n cks --key=key.pem --cert=cert.pem


$ vi secure-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
  name: secure-ingress
  namespace: cks
spec:
  ingressClassName: nginx
  tls:
  - hosts:
      - secure-ingress.com
    secretName: secure-ingress-tls
  rules:
  - host: secure-ingress.com
    http:
      paths:
      - backend:
          service:
            name: service1
            port:
              number: 80
        path: /service1
        pathType: Exact
      - backend:
          service:
            name: service2
            port:
              number: 80
        path: /service2
        pathType: Exact


##----------------------------------------
## secure-ingress.com 으로 호출
##----------------------------------------
$ curl -kv https://secure-ingress.com:32443/service1 --resolve secure-ingress.com:32443:10.0.145.156
...
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=secure-ingress.com
*  start date: Nov 24 12:05:32 2021 GMT
*  expire date: Nov 24 12:05:32 2022 GMT
*  issuer: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=secure-ingress.com
*  SSL certificate verify result: self signed certificate (18), continuing anyway.


```









# 3. System Hardening

### AppArmor - linux

```bash
##----------------------------------------
## apparmor enforce 적용 현황 보기
##----------------------------------------
$ aa-status


##----------------------------------------
## file 생성
##----------------------------------------
$ mkdir -p apparmor && cd apparmor

$ vi myscript.sh
#!/bin/bash
touch /tmp/file.txt
echo "New File created"

rm -f /tmp/file.txt
echo "New file removed"


$ chmod +x myscript.sh
$ ./myscript.sh


##----------------------------------------
## generate a new profile
##----------------------------------------
$ aa-genprof ./myscript.sh


##----------------------------------------
## verify the new profile
##----------------------------------------
$ cat /etc/apparmor.d/root.apparmor.myscript.sh


##----------------------------------------
## disable profile
##----------------------------------------
ln -s /etc/apparmor.d/root.apparmor.myscript.sh /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/root.apparmor.myscript.sh

```



### AppArmor - Kubernetes

```bash
##----------------------------------------
## create a simple profile in node
##----------------------------------------
$ sudo apparmor_parser -q <<EOF
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}
EOF


##----------------------------------------
## create a pod
##----------------------------------------
apiVersion: v1
kind: Pod
metadata:
  name: hello-apparmor
  annotations:
    # Tell Kubernetes to apply the AppArmor profile "k8s-apparmor-example-deny-write".
    # Note that this is ignored if the Kubernetes node is not running version 1.4 or greater.
    container.apparmor.security.beta.kubernetes.io/hello: localhost/k8s-apparmor-example-deny-write
spec:
  containers:
  - name: hello
    image: busybox
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]


```





### gVisor

검색어: runtime class

```bash
##----------------------------------------
## create a RuntimeClass
##----------------------------------------
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc


##----------------------------------------
## create a pod
##----------------------------------------
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  runtimeClassName: gvisor
  containers:
  - name: nginx
    image: nginx
```



### Network Policy

```bash
##----------------------------------------
## Default deny Ingress and Egress
##----------------------------------------
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Inress
  - Egress
  
  
##----------------------------------------
## only run=pod1 deny Ingress and Egress
##----------------------------------------
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector:
    matchLabels:
      run: pod1
  policyTypes:
  - Inress
  - Egress
```





# 4. Supply Chain Security

### Trivy

```bash
$ trivy image --severity HIGH,CRITICAL nginx:1.19.5
```



### Checkov







# 5. Runtime Security

### Falco

```bash
##----------------------------------------
## falco rule
##----------------------------------------
$ vi /etc/falco/falco_rules.local.yaml

- macro: custom_macro
  condition: evt.type = execve and container.id != host

- list: blacklist_binaries
  items: [cat, grep, date]

- rule: The program "cat" is run in a container
  desc: An event will trigger every time you run cat in a container
  condition: custom_macro and proc.name in (blacklist_binaries)
  output: "exam cat was run inside a container (user=%user.name container=%container.name image=%container.image proc=%proc.cmdline)"
  priority: INFO


##----------------------------------------
## falco 실행
##----------------------------------------
$ timeout 25s falco | grep exam
```



### sysdig

```bash
$ sysdig proc.name=vim or proc.name=cat
```



### Immutable Container Runtime

```bash
$ vi immutable-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: immutable-pod
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep", "3600"]
    securityContext:
      readOnlyRootFileSystem: true
```















======================= 참고 ==========================================



### Metadata deny

```bash
##----------------------------------------
## node 에서 metadata 호출
##----------------------------------------
$ curl http://169.254.169.254/latest/meta-data/


##----------------------------------------
## pod 에서 metadata 호출 성공
##----------------------------------------
$ kubectl run nginx -n cks --image nginx
$ kubectl exec nginx -n cks -- curl http://169.254.169.254/latest/meta-data/


$ vi network-policy-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-deny
  namespace: cks
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32

##----------------------------------------
## pod 에서 metadata 호출 실패
##----------------------------------------
$ kubectl exec nginx -n cks -- curl http://169.254.169.254/latest/meta-data/



$ vi network-policy-allow.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-metadata-allow
  namespace: cks
spec:
  podSelector:
    matchLabels:
      metadata-access-enabled: "true"
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 169.254.169.254/32



$ kubectl get pods -n cks --show-labels
NAME    READY   STATUS    RESTARTS   AGE     LABELS
nginx   1/1     Running   0          8m56s   run=nginx
pod1    1/1     Running   0          48m     run=pod1
pod2    1/1     Running   0          48m     run=pod2


$ kubectl label pod nginx -n cks metadata-access-enabled=true

##----------------------------------------
## pod 에서 metadata 호출 성공
##----------------------------------------
$ kubectl exec nginx -n cks -- curl http://169.254.169.254/latest/meta-data/
```





### CIS benchmarks for kubernetes

https://www.cisecurity.org/benchmark/kubernetes/



### Kube-bench

https://github.com/aquasecurity/kube-bench

```bash
$ kubectl apply -f job.yaml
```





### Role and Rolebinding

```bash
$ kubectl create ns red
$ kubectl create ns blue


##------------------------------------------------------
## role -> rolebinding
##------------------------------------------------------
$ kubectl create role secret-manager -n red --verb=get --resource=secrets --dry-run=client -o yaml
$ kubectl create rolebinding secret-manager -n red --role=secret-manager --user=ahnsk --dry-run=client -o yaml


##------------------------------------------------------
## role -> rolebinding
##------------------------------------------------------
$ kubectl create role secret-manager -n blue --verb=get,list --resource=secrets --dry-run=client -o yaml
$ kubectl create rolebinding secret-manager -n blue --role=secret-manager --user=ahnsk --dry-run=client -o yaml

$ kubectl auth can-i get secrets -n red --as ahnsk



$ kubectl create clusterrole deploy-deleter --verb delete --resource deployments
##------------------------------------------------------
## clusterrole -> clusterrolebinding
##------------------------------------------------------
$ kubectl create clusterrolebinding deploy-deleter --user ahnsk --clusterrole deploy-deleter

##------------------------------------------------------
## clusterrole -> rolebinding
##------------------------------------------------------
$ kubectl create rolebinding deploy-deleter -n red --user seungkyu --clusterrole deploy-deleter

$ kubectl auth can-i delete deployments --as seungkyu -n red
```





### CSR - Certificate Signing Request

검색어: certificatesigningrequest

```bash
$ openssl genrsa -out ahnsk.key 2048
$ openssl req -new -key ahnsk.key -out ahnsk.csr
...
Common Name (e.g. server FQDN or YOUR name) []:ahnsk
...


$ cat ahnsk.csr | base64 -w 0
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21qQ0NBWUlDQVFBd1ZURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeApJVEFmQmdOVkJBb01HRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERU9NQXdHQTFVRUF3d0ZZV2h1CmMyc3dnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDaCszUEpMYWZ5WHRtcy9hWWUKcWdiYjRaMU1rWGs3Mkl5dTNTV0pNRndkM0FLTUZ4VDZUeVI3TFlQd0MrRjBnU0cvb2c3dHl4VDJqU1g5a00yWgpsWldLUzhHQUpFaTVrMU5WN242WWUyTThFQUF6RjBRS3BqN2haZUVNQjFGbWtyM08reW9iazI0c0F3NFd2eEJXClZod0sxMVRCRU5CaGR5NFM2Y2dLWmorZ0JvTktQbmVMNU5LNTN1UWIzMFJDY1dNOFg2d00wbWxNcDAzUGo0czcKWmxxVm5WaG43a01UUStwWTdWZmxvbGRVYk91RStTeEp4bTF0Q004OW84bDJzaFRadHRySEYxSVB4dXAzN1pOcQpaWFJvY2Q3UXQ5Q2VzR1VXWVUxaFNXdlZoaCtSWVptL2FlQWwzTUlnNno0WjQxSVJFb3MyVlNLV2xFM3Z5NmhICnRHcnhBZ01CQUFHZ0FEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFVd1BtYlNtd2Y4TXZiOSszTmU0WW5GV28KSktZMjluTU5aYUIzUi9jRktCQW1mWGoyeG0wTC9lN053MzZ5b1JJbmNSU0ZVRlVGR2tQNnJiYkxQTDRvTlM2dwpGN28reC9sRTBSbmJEcnE2OFJkUm5iZWQrekU5T2hLV1RzVHVXTFVPdjdGcmFjVzBSNHFsTllUckZoWitOcThJCmJlNXF0UXg3TXVwa3ZpdDYwNEVaZTI1SHVaSUlHOVhsTWpvVnhXbjkzODhsOWZKWG9ZYnZXNldmem9sMmFYRkIKQU15NVB1QXE0cTN6TTJjRzJWenJDVGpPdU41NmNpYytqbGJydkRKRlQ1ZEc1cVpHcE1ZYjFkcy9BRTZ0ZTN3dQpUbGwvbktaUThRb2tlV1RzYkVUZ1h3N2RMVHZRbnd3YVF6SVNWTkhrcTlUS0F1VlF4U01va3lxUStCV3NWUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=



##------------------------------------------------------
## kubernetes v1.20.x 버전의 csr spec
##------------------------------------------------------
$ csr.yaml
---
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ahnsk
spec:
  groups:
  - system:authenticated
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21qQ0NBWUlDQVFBd1ZURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeApJVEFmQmdOVkJBb01HRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERU9NQXdHQTFVRUF3d0ZZV2h1CmMyc3dnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDaCszUEpMYWZ5WHRtcy9hWWUKcWdiYjRaMU1rWGs3Mkl5dTNTV0pNRndkM0FLTUZ4VDZUeVI3TFlQd0MrRjBnU0cvb2c3dHl4VDJqU1g5a00yWgpsWldLUzhHQUpFaTVrMU5WN242WWUyTThFQUF6RjBRS3BqN2haZUVNQjFGbWtyM08reW9iazI0c0F3NFd2eEJXClZod0sxMVRCRU5CaGR5NFM2Y2dLWmorZ0JvTktQbmVMNU5LNTN1UWIzMFJDY1dNOFg2d00wbWxNcDAzUGo0czcKWmxxVm5WaG43a01UUStwWTdWZmxvbGRVYk91RStTeEp4bTF0Q004OW84bDJzaFRadHRySEYxSVB4dXAzN1pOcQpaWFJvY2Q3UXQ5Q2VzR1VXWVUxaFNXdlZoaCtSWVptL2FlQWwzTUlnNno0WjQxSVJFb3MyVlNLV2xFM3Z5NmhICnRHcnhBZ01CQUFHZ0FEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFVd1BtYlNtd2Y4TXZiOSszTmU0WW5GV28KSktZMjluTU5aYUIzUi9jRktCQW1mWGoyeG0wTC9lN053MzZ5b1JJbmNSU0ZVRlVGR2tQNnJiYkxQTDRvTlM2dwpGN28reC9sRTBSbmJEcnE2OFJkUm5iZWQrekU5T2hLV1RzVHVXTFVPdjdGcmFjVzBSNHFsTllUckZoWitOcThJCmJlNXF0UXg3TXVwa3ZpdDYwNEVaZTI1SHVaSUlHOVhsTWpvVnhXbjkzODhsOWZKWG9ZYnZXNldmem9sMmFYRkIKQU15NVB1QXE0cTN6TTJjRzJWenJDVGpPdU41NmNpYytqbGJydkRKRlQ1ZEc1cVpHcE1ZYjFkcy9BRTZ0ZTN3dQpUbGwvbktaUThRb2tlV1RzYkVUZ1h3N2RMVHZRbnd3YVF6SVNWTkhrcTlUS0F1VlF4U01va3lxUStCV3NWUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth



$ kubectl apply -f csr.yaml
certificatesigningrequest.certificates.k8s.io/ahnsk created

$ kubectl get csr
NAME    AGE   SIGNERNAME                            REQUESTOR          CONDITION
ahnsk   5s    kubernetes.io/kube-apiserver-client   kubernetes-admin   Pending


$ kubectl certificate approve ahnsk
certificatesigningrequest.certificates.k8s.io/ahnsk approved

$ kubectl get csr
NAME    AGE     SIGNERNAME                            REQUESTOR          CONDITION
ahnsk   2m26s   kubernetes.io/kube-apiserver-client   kubernetes-admin   Approved,Issued

$ kubectl get csr ahnsk -o yaml
...
status:
  certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURHVENDQWdHZ0F3SUJBZ0lRYi90angycklqWXpFN2EwOFVXdW5FVEFOQmdrcWhraUc5dzBCQVFzRkFEQVYKTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1CNFhEVEl4TVRFeU5qRXhOVE0xTlZvWERUSXlNVEV5TmpFeApOVE0xTlZvd1ZURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdUQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WCkJBb1RHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERU9NQXdHQTFVRUF4TUZZV2h1YzJzd2dnRWkKTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDaCszUEpMYWZ5WHRtcy9hWWVxZ2JiNFoxTQprWGs3Mkl5dTNTV0pNRndkM0FLTUZ4VDZUeVI3TFlQd0MrRjBnU0cvb2c3dHl4VDJqU1g5a00yWmxaV0tTOEdBCkpFaTVrMU5WN242WWUyTThFQUF6RjBRS3BqN2haZUVNQjFGbWtyM08reW9iazI0c0F3NFd2eEJXVmh3SzExVEIKRU5CaGR5NFM2Y2dLWmorZ0JvTktQbmVMNU5LNTN1UWIzMFJDY1dNOFg2d00wbWxNcDAzUGo0czdabHFWblZobgo3a01UUStwWTdWZmxvbGRVYk91RStTeEp4bTF0Q004OW84bDJzaFRadHRySEYxSVB4dXAzN1pOcVpYUm9jZDdRCnQ5Q2VzR1VXWVUxaFNXdlZoaCtSWVptL2FlQWwzTUlnNno0WjQxSVJFb3MyVlNLV2xFM3Z5NmhIdEdyeEFnTUIKQUFHakpUQWpNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01DTUF3R0ExVWRFd0VCL3dRQ01BQXdEUVlKS29aSQpodmNOQVFFTEJRQURnZ0VCQUdDQlRwN3lFUkJVaU05NG1HYlZQbmMySHUxTVhJc3ZMcTRvSm4xZG9MRnNNWExhCkRGdzBROTBESHVyWEdFdGg5clZyMHJFNkl5UU5LbkpCY2Rqd1JCZFZ3VjFUSTYvSTZNTVBhQzNXY0lPdHpSMDMKOGhXaEZDc1U2Ky9OTmYrQmErQzdQQ2laQSs3dEpFVTJNZEh4ajhYaktNSzEzaCsyRUY5RzFjaHlnZGdPcWxmVQoxTVQvQ3Rzd1B0dFhBVkpwd3pBM3c0Y1VBajVwZ01OMWU3WGdJNE80djBpdnJHTVpDYXZmR296VWxaSm0vWmhzCno5Y0RndHM5NldHZjMzS0g2eE9KTWxJaGtrUUNrMndUM3Q5cFpzMnF0S3FpK1BiUVc3ZU1ZMFZOdi84RW9BNFEKZmovcEU2YVd6aGcvY2NURTNRV1p5YVZIZnVZbHhQMnJvSDNjdFdRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
...

##------------------------------------------------------
## ahnsk cert 얻기
##------------------------------------------------------
$ echo LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURHVENDQWdHZ0F3SUJBZ0lRYi90angycklqWXpFN2EwOFVXdW5FVEFOQmdrcWhraUc5dzBCQVFzRkFEQVYKTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1CNFhEVEl4TVRFeU5qRXhOVE0xTlZvWERUSXlNVEV5TmpFeApOVE0xTlZvd1ZURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdUQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WCkJBb1RHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERU9NQXdHQTFVRUF4TUZZV2h1YzJzd2dnRWkKTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDaCszUEpMYWZ5WHRtcy9hWWVxZ2JiNFoxTQprWGs3Mkl5dTNTV0pNRndkM0FLTUZ4VDZUeVI3TFlQd0MrRjBnU0cvb2c3dHl4VDJqU1g5a00yWmxaV0tTOEdBCkpFaTVrMU5WN242WWUyTThFQUF6RjBRS3BqN2haZUVNQjFGbWtyM08reW9iazI0c0F3NFd2eEJXVmh3SzExVEIKRU5CaGR5NFM2Y2dLWmorZ0JvTktQbmVMNU5LNTN1UWIzMFJDY1dNOFg2d00wbWxNcDAzUGo0czdabHFWblZobgo3a01UUStwWTdWZmxvbGRVYk91RStTeEp4bTF0Q004OW84bDJzaFRadHRySEYxSVB4dXAzN1pOcVpYUm9jZDdRCnQ5Q2VzR1VXWVUxaFNXdlZoaCtSWVptL2FlQWwzTUlnNno0WjQxSVJFb3MyVlNLV2xFM3Z5NmhIdEdyeEFnTUIKQUFHakpUQWpNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01DTUF3R0ExVWRFd0VCL3dRQ01BQXdEUVlKS29aSQpodmNOQVFFTEJRQURnZ0VCQUdDQlRwN3lFUkJVaU05NG1HYlZQbmMySHUxTVhJc3ZMcTRvSm4xZG9MRnNNWExhCkRGdzBROTBESHVyWEdFdGg5clZyMHJFNkl5UU5LbkpCY2Rqd1JCZFZ3VjFUSTYvSTZNTVBhQzNXY0lPdHpSMDMKOGhXaEZDc1U2Ky9OTmYrQmErQzdQQ2laQSs3dEpFVTJNZEh4ajhYaktNSzEzaCsyRUY5RzFjaHlnZGdPcWxmVQoxTVQvQ3Rzd1B0dFhBVkpwd3pBM3c0Y1VBajVwZ01OMWU3WGdJNE80djBpdnJHTVpDYXZmR296VWxaSm0vWmhzCno5Y0RndHM5NldHZjMzS0g2eE9KTWxJaGtrUUNrMndUM3Q5cFpzMnF0S3FpK1BiUVc3ZU1ZMFZOdi84RW9BNFEKZmovcEU2YVd6aGcvY2NURTNRV1p5YVZIZnVZbHhQMnJvSDNjdFdRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg== | base64 -d > ahnsk.crt


$ kubectl config set-credentials ahnsk --client-key ahnsk.key --client-certificate ahnsk.crt --embed-certs
$ kubectl config set-context ahnsk --user ahnsk --cluster kubernetes
$ kubectl config use-context ahnsk

##------------------------------------------------------
## ahnsk 사용자 권한별 조회
##------------------------------------------------------
$ kubectl get ns
Error from server (Forbidden): namespaces is forbidden: User "ahnsk" cannot list resource "namespaces" in API group "" at the cluster scope

$ kubectl get secret -n blue

```



### ServiceAccount

```bash
$ curl -k https://kubernetes -H "Authorization: Bearer xxxxxxxxxxx"

$ kubectl create clusterrolebinding accessor --clusterrole edit --serviceaccount default:accessor
$ kubectl auth can-i delete secrets --as system:serviceaccount:default:accessor
```





### Cert 보기

```bash
$ openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout
```





### NodeRestriction

```bash
kube-apiserver    --enabled-admission-plugins=NodeRestriction
```





### Kubernetes Upgrade

```bash
##------------------------------------------------------
## master 노드 upgrade
##------------------------------------------------------
$ kubectl drain k1-master --ignore-daemonsets

$ sudo app-cache show kubeadm | grep 1.19
$ sudo apt-get install kubeadm=1.19.3-00 kubectl=1.19.3-00

$ kubeadm upgrade plan
$ kubeadm upgrade apply v1.19.3

$ sudo apt-get install kubelet=1.19.3-00 
$ kubectl uncordon k1-master01

##------------------------------------------------------
## worker 노드 upgrade
##------------------------------------------------------
$ kubectl drain k1-node --ignore-daemonsets
$ sudo apt-get install kubeadm=1.19.3-00

$ kubeadm upgrade node

$ sudo apt-get install kubelet=1.19.3-00
$ kubectl uncordon k1-node
```





### Secret - volume and env

검색어: configure a pod to use secret

```bash
##------------------------------------------------------
## volume 으로 활용
##------------------------------------------------------
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: mypod
    image: redis
    volumeMounts:
    - name: foo
      mountPath: "/etc/foo"
  volumes:
  - name: foo
    secret:
      secretName: mysecret


##------------------------------------------------------
## env 로 활용
##------------------------------------------------------
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
      - name: SECRET_PASSWORD
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: password
```



### etcd

```bash
$ ETCDCTL_API=3 etcdctl \
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/apiserver-etcd-client.crt \
--key /etc/kubernetes/pki/apiserver-etcd-client.key \
endpoint health


##------------------------------------------------------
## default 네임스페이스의 default-token-ncdcf 값을 조회
##------------------------------------------------------
$ ETCDCTL_API=3 etcdctl \
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/apiserver-etcd-client.crt \
--key /etc/kubernetes/pki/apiserver-etcd-client.key \
/registry/secrets/default/default-token-ncdcf
```













### OPA

gatekeeper playground: https://play.openpolicyagent.org/

gatekeeper policy examples:  https://github.com/bouweceunen/gatekeeper-policies





### Dockerfile

https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

```bash
package main

import (
    "fmt"
    "time"
    "os/user"
)

func main () {
    user, err := user.Current()
    if err != nil {
        panic(err)
    }

    for {
        fmt.Println("user: " + user.Username + " id: " + user.Uid)
        time.Sleep(1 * time.Second)
    }
}




FROM ubuntu
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y golang-go
COPY app.go .
RUN CGO_ENABLED=0 go build app.go

FROM alpine:3.12.1
RUN chmod a-w /etc
RUN addgroup -S appgroup && adduser -S appuser -G appgroup -H /home/appuser
RUN rm -rf /bin/*
COPY --from=0 /app /home/appuser/
USER appuser
CMD ["/home/appuser/app"]
```



### KubeSec

https://github.com/controlplaneio/kubesec

kubsec playground: https://kubesec.io/





### port  찾기

```bash
$ netstat -plnt | grep 22

$ lsof -i :22
```



### systemctl and service

```bash
$ systemctl list-units --type=service --state=running | grep snapd
```







# 부록. Exam Preparation Practice Tests

### 01. **ImagePolicyWebhook**

1. All the images that are deployed need to be verified from an external webhook.
2. URL of the webhook is webhook.kplabs.internal
3. If the webhook is down, the images should not be allowed.
4. All files should be stored in /etc/kubernetes/confcontrol
5. For CA certificate, use the ca.crt available under /etc/kubernetes/pki directory
6. For user certificate and key, use the API Certificate and Key configured under pki directory.
7. Create a POD named nginx from an image of nginx
8. If POD fails to start, copy the error log and store it to /tmp/error.log

```bash
$ mkdir -p mkdir /etc/kubernetes/confcontrol

$ vi /etc/kubernetes/confcontrol/admission_config.yaml
---
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/confcontrol/kubeconfig.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: false


##---------------------------------------------------------
## user 의 name 을 apiserver 로 해야함
##---------------------------------------------------------
$ vi /etc/kubernetes/confcontrol/kubeconfig.yaml
apiVersion: v1
kind: Config
contexts:
- context:
    cluster: imagepolicy-service
    user: apiserver
  name: apiserver@imagepolicy-service
current-context: apiserver@imagepolicy-service
clusters:
- name: imagepolicy-service
  cluster:
    certificate-authority: /etc/kubernetes/ssl/ca.crt
    server: https://webhook.kplabs.internal
users:
- name: apiserver
  user:
    client-certificate: /etc/kubernetes/ssl/apiserver.crt
    client-key: /etc/kubernetes/ssl/apiserver.key


$ vi /etc/kubernetes/manifests/kube-apiserver.yaml

    - --enable-admission-plugins=NodeRestriction,PodSecurityPolicy,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/confcontrol/admission_config.yaml

    volumeMounts:
    - mountPath: /etc/kubernetes/confcontrol
      name: image-webhook
      readOnly: true
...
  volumes:
  - hostPath:
      path: /etc/kubernetes/confcontrol
      type: DirectoryOrCreate
    name: image-webhook




$ kubectl run nginx --image=nginx
Error from server (Forbidden): pods "nginx" is forbidden: Post "https://webhook.kplabs.internal/?timeout=30s": dial tcp: lookup webhook.kplabs.internal on 8.8.8.8:53: no such host


$ echo 'Error from server (Forbidden): pods "nginx" is forbidden: Post "https://webhook.kplabs.internal/?timeout=30s": dial tcp: lookup webhook.kplabs.internal on 8.8.8.8:53: no such host' > /tmp/error.log
```





### 02. AppArmor

1. Load the profile into enforcing mode.
2. Create a deployment named pod-deploy with 2 replicas using the image of busybox.
3. The name of a container should be busybox-container
4. The busybox should run with the following command - sleep 36000
5. After deployment and PODS are created, associate the PODS with the AppArmor profile.

```bash
$ ssh k1-node02


$ apparmor_parser -q <<EOF
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}
EOF


$ aa-status | grep k8s-apparmor-example-deny-write
   k8s-apparmor-example-deny-write


$ kubectl create deploy pod-deploy -n cks --image=busybox --replicas=2 --dry-run=client -o yaml > deploy-node02.yaml


##---------------------------------------------------------
## annotations 을 spec.template.metadata 아래 pod 에 넣어야 함
##---------------------------------------------------------
$ vi deploy-node02.yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-deploy
  namespace: cks
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pod-deploy
  template:
    metadata:
      annotations:
        container.apparmor.security.beta.kubernetes.io/busybox-container: localhost/k8s-apparmor-example-deny-write
      labels:
        app: pod-deploy
    spec:
      containers:
      - image: busybox
        name: busybox-container
        command:
        - sleep
        - "36000"
      nodeSelector:
        kubernetes.io/hostname: k1-node02

```





### 3. Auditing

1.  Log all namespace events at RequestResponse
2. Log all PODS events at Request.
3. No configmaps related events should be logged.
4. All other events should be stored at metadata level.
5. There should be maximum log files of 3.
6. Policy configuration should be available at /etc/kubernetes/audit-policy.yaml
7. Logs should be stored in a /var/log/audit.log

```bash
$ vi /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["namespaces"]
  - level: Request
    resources:
    - group: ""
      resources: ["pods"]
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
  - level: Metadata



$ vi /etc/kubernetes/manifests/kube-apiserver.yaml

    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-path=/var/log/audit.log
    - --audit-log-maxbackup=3

    volumeMounts
    - mountPath: /etc/kubernetes/audit-policy.yaml
      name: audit-file
    - mountPath: /var/log/audit.log
      name: log-file
  volumes
  - hostPath:
      path: /etc/kubernetes/audit-policy.yaml
      type: File
    name: audit-file
  - hostPath:
      path: /var/log/audit.log
      type: FileOrCreate
    name: log-file
```



### 4. Secrets

1. Part 1 -

2. Run the following command:

3. i) kubectl apply -f https://raw.githubusercontent.com/zealvora/myrepo/master/cks/secrets.yaml

4. For the custom secret in the namespace cks, fetch the content values in plain-text and store it to /tmp/secret.txt

   

5. Part 2 - 

6. Create a new secret named mount-secret with following contents 

7. username=dbadmin

8. password=dbpasswd123 

9. Mount the demo-secret to a POD named secret-pod. The secret should be available to /etc/mount-secret

```bash
apiVersion: v1
kind: Namespace
metadata:
  name: cks

---
apiVersion: v1
data:
  admin: cGFzc3dvcmQ=
kind: Secret
metadata:
  name: demo-secret
  namespace: cks
  
  
$ kubectl get secret -n cks demo-secret -o jsonpath='{.data.admin}' | base64 -d
password

$ echo 'admin=password' >  /tmp/secret.txt

$ kubectl create secret generic mount-secret -n cks --from-literal=username=dbadmin --from-literal=password=dbpasswd123

$ kubectl run secret-pod -n cks --image=nginx --dry-run=client -o yaml > secret-pod.yaml

$ vi secret-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
  namespace: cks
spec:
  containers:
  - image: nginx
    name: secret-pod
    volumeMounts:
    - name: sp
      mountPath: /etc/mount-secret
  volumes:
  - name: sp
    secret:
      secretName: demo-secret
```





### 5. Service Account and RBAC

1. Create a new Service Account named new-sa in the cks namespace.
2. The SA should have permission to list secrets
3. Associate the SA with a pod named nginx-pod

```bash
$ kubectl create sa new-sa -n cks

$ kubectl create role secret-reader --verb=list --resource=secrets -n cks --dry-run=client -o  yaml > role.yaml

$ role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: cks
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - list
  
  
$ kubectl create rolebinding secret-rolebinding -n cks --role secret-reader --serviceaccount=cks:new-sa --dry-run=client -o  yaml > rolebinding.yaml

$ vi rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-rolebinding
  namespace: cks
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: new-sa
  namespace: cks
  
  
$ kubectl run nginx-pod -n cks --image=nginx --serviceaccount=new-sa --dry-run=client -o yaml > pod.yaml

$ vi pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: cks
spec:
  containers:
  - image: nginx
    name: nginx-pod
  serviceAccountName: new-sa
  
$ kubectl exec -it  -n cks nginx-pod -- bash
/# cd /run/secrets/kubernetes.io/serviceaccount
/# TOKEN=$(cat token)
/# curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local/api/v1/namespaces/cks/secrets
```



### 6. Privileged and Immutability

1. There are a few PODS running in a namespace named selector.
2. For all the PODS that use privileged containers OR do not follow immutability, delete them.

```bash
$ vi selector.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: selector
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-1
  namespace: selector
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep","36000"]
    securityContext:
      readOnlyRootFilesystem: true
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-2
  namespace: selector
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep","36000"]
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-3
  namespace: selector
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep","36000"]
    securityContext:
       privileged: true



$ kubectl get pods -n selector

$ kubectl get pods -o yaml -n selector | grep -i privileged

$ kubectl get pods -o yaml -n selector | grep -i readOnlyRootFilesystem
```





### 7. Trivy

Install Trivy and Scan the following images for High and Critical Vulnerability

1. Image of kube-apiserver running
2. Nginx image 1.19.2

```bash
$ trivy image --severity HIGH,CRITICAL nginx:1.19.2
```





### 8. Sysdig / Falco

1. Install Falco
2. For all the containers, find a list of all new and spawned processes.
3. Store the data in format of \[time]\[process-name][uid]
4. Run for 30 seconds.
5. Store the output in /tmp/falco.txt

```bash
https://falco.org/docs/rules/#macros

$ vi /etc/falco/falco_rules.local.yaml

- macro: spawned_process
  condition: evt.type = execve and evt.dir=<

- rule: spawned-process
  desc: Spawned process
  condition: spawned_process and container.id != host
  output: spawned %evt.time %proc.name %user.uid
  priority: ERROR


$ timeout 30s falco | grep spawned > spawn.txt

$ cat spawn.txt | awk '{print $4 " " $5 " " $6}' > /tmp/falco.txt

```





### 9. Pod Security Policy

1. Create a new PSP named psp-restrictive which denies privileged PODS.
2. Create a cluster role named psp-restrictive that uses the PSP.
3. Create a Cluster Role Binding that associates the Cluster Role to SA named default in namespace test

```bash
$ vi psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp-restrictive
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'


$ vi clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp-restrictive
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - psp-restrictive


$ vi clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: psp-restrictive
roleRef:
  kind: ClusterRole
  name: psp-restrictive
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: default
  namespace: test



##---------------------------------------------------------
## kube-apiserver 의 admission plugin 에 PodSecurityPolicy 를 추가해야 함
##---------------------------------------------------------
$ vi /etc/kubernetes/manifests/kube-apiserver.yaml

- --enable-admission-plugins=NodeRestriction,PodSecurityPolicy

```





### 10. CIS Benchmark

1. Authorization Mode should be Node and RBAC
2. AlwaysPullImages Admission controller must be enabled.
3. Anonymous Auth is set to false for Kubelet
4. Certificate Authentication is enabled for ETCD

```bash
$ vi /etc/kubernetes/manifests/kube-apiserver.yaml

- --authorization-mode=Node,RBAC
- --enable-admission-plugins=NodeRestriction,AlwaysPullImages


$ vi /var/lib/kubelet/config.yaml

authentication:
  anonymous:
    enabled: false

$ vi /etc/kubernetes/manifests/etcd.yaml

- --client-cert-auth=true
```





### 11. Network Policy

Create a new namespace named `custom-namespace`

Create a new network policy named `my-network-policy` in the `custom-namespace.`

1. Network Policy should allow PODS within the custom-namespace to connect to each other only on Port 80. No other ports should be allowed.
2. No PODs from outside of the custom-namespace should be able to connect to any pods inside the custom-namespace.

```bash

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-network-policy
  namespace: custom-namespace
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
    ports:
    - port: 80
```



### 12. Network Policy

Create a network policy that following the below requirements

1. PODS with a Label of color=blue should only allow traffic from PODs with label color=red on Port 80.

```bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-network-policy
spec:
  podSelector:
    matchLabels:
      color: blue
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          color: red
    ports:
    - port: 80
```





### 13. Network policy

1. Create a namespace named color-namespace
2. Allow ingress traffic from pod labeled color=red in a namespace with label color=bright

```bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-network-policy
  namespace: color-namespace
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          color: bright
      podSelector:
        matchLabels:
          color: red
```





### 14. Network Policy

Allow outbound traffic to other PODS in the same namespace only to the POD with label color=yellow on Port 80

```bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-network-policy
spec:
  podSelector: {}
  policyTypes:
  - Egress
  Egress:
  - to:
    - podSelector:
        matchLabels:
          color: yellow
    ports:
    - port: 80
```





### 15. gVisor

For K8s v1.19, runtimeclass belonged to `apiVersion: node.k8s.io/v1beta1` however, from K8s 1.20, it belongs to `apiVersion: node.k8s.io/v1`

For exams based on 1.20, make sure you remember this.

1. Create a new RunTimeClass named gvisor-class which should use the handler of runsc.
2. Create a deployment named gvisor-deploy with nginx image and 3 replicas.
3. Modify the deployment to ensure it uses the custom gvisor-class.

```bash
##---------------------------------------------------------
## gvisor 는 runtimeclass 로 검색해야 함
##---------------------------------------------------------
$ vi runtimeclass.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor-class
handler: runsc


$ kubectl create deploy gvisor-deploy -n cks --image nginx --replicas=3 --dry-run=client -o yaml > deploy.yaml


$ vi deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gvisor-deploy
  namespace: cks
spec:
  replicas: 3
  selector:
    matchLabels:
      app: gvisor-deploy
  template:
    metadata:
      labels:
        app: gvisor-deploy
    spec:
      containers:
      - image: nginx
        name: nginx
      runtimeClassName: gvisor-class


```



### 16. Static Analysis

Following are the two files of deployment and Dockerfile. Modify this file to remove security configuration and store it in the following path:

1. /tmp/secure-pod.yaml
2. /tmp/secure-Dockerfile

Note: Do not add/remove lines, just modify existing lines.

**POD Configuration (Fix 1 security misconfiguration)**

```bash
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo
    securityContext:
      privileged: true
      readOnlyRootFilesystem: true
```

**Dockerfile (fix 2 security misconfiguration)**

The application requires Ubuntu 16.04 image. Fix two security misconfiguration

```bash
FROM ubuntu:latest
COPY apps /opt/apps/
RUN opkg update
RUN useradd app-user 
USER root
CMD ["/opt/apps/loop_app"]
```



**정답**

```
Step 1 - POD Misconfiguration

We see that privileged is set to true, you can change it to false.

Step 2 - POD Misconfiguration

Since the application requires ubuntu:16.04 image however FROM instruction has ubuntu:latest. You can change it to ubuntu:16.04

USER is set to root. Change it to the user that is created with useradd command (app-user)
```



