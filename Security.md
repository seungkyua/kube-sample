https://itnext.io/cks-exam-series-1-create-cluster-security-best-practices-50e35aaa67ae



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



### Encrypted etcd

검색어: encryptionconfiguration

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





### ImagePolicyWebhook

https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook

```bash
kube-apiserver

- --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
- --enable-admission-plugins=ImagePolicyWebhook


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
      defaultAllow: true
      

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



### Falco



### port  찾기

```bash
$ netstat -plnt | grep 22

$ lsof -i :22
```



### systemctl and service

```bash
$ systemctl list-units --type=service --state=running | grep snapd
```





