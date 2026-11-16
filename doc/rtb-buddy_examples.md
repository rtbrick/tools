---
theme:
  name: catppuccin-mocha
  override:
    code:
      alignment: left
#      background: false
---

rtb-buddy: why, what, what else
====
<!-- alignment: center -->
<span style="color: blue">Chris Lenz, chris@rthrick.com</span>
> [!WARNING] lab-only, don't accidentally run them in the wrong environment.
<!-- end_slide -->

rtb-buddy: why
====
* regardless how hard you try, some things are complicated
* give simple commands to help customers to deal with complicated things
  * give possibility to automate things by opensourcing the buddy 
<!-- end_slide -->

Topology Manager: Reserve the topology
===

```bash +exec
rtb-test tm subscribe --type STD-40 --asic hw --priority 5 --instance 3213040 --usage 2h --id f23a1a4a-fc03-47af-b29a-cfa4769c2295 --skip-hw-spawn
```
<!-- end_slide -->

Generate JWKS file
===

```bash +exec
rtb-buddy apigw generate jwks
```  
generates
* apigw-jwks-priv.json **used to generate tokens**
* apigw-jwks.json **this is handed over to apigwd to validate the tokens**
<!-- end_slide -->

Generate a tls certificate
===
```bash +exec
rtb-buddy apigw generate tls \
          --org rtbrick  
```
generates
* server.crt
* server.key  **needed for apigwd to server tls, we generate by default one on the apigwd first start, but is self signed and nobody will trust ;-)**
<!-- end_slide -->

Generate a token
===
```bash +exec
rtb-buddy apigw generate token
```
<!-- end_slide -->

Inspect a token
===
```bash +exec
rtb-buddy apigw generate token | rtb-buddy apigw inspect token
```
<!-- end_slide -->

Copy rtbrick default jwks files
===
```bash +exec
cp ../rtblab/apigw-jwks-priv.json .
cp ../rtblab/apigw-jwks.json .
```  
<!-- end_slide -->

Restconf get
===
```bash +exec
rtb-buddy rbfs config restconf get ufi12.q2a.u38.r1.blr.rtbrick.net
```
<!-- end_slide -->

Restconf get over https and authenticated via token
===
```bash +exec
rtb-buddy rbfs config restconf get ufi12.q2a.u38.r1.blr.rtbrick.net --auth-mode
```
<!-- end_slide -->

Load a specific path
===
```bash +exec
rtb-buddy rbfs config restconf get -p "rtbrick-config:lawful-intercept" ufi12.q2a.u38.r1.blr.rtbrick.net
```
<!-- end_slide -->

Load a specific path and store in file
===
```bash +exec  
rtb-buddy rbfs config restconf get -p "rtbrick-config:lawful-intercept" ufi12.q2a.u38.r1.blr.rtbrick.net -o ufi12.law1.json
```
<!-- end_slide -->

Generate a root ca for an organization
===
```bash +exec  
rtb-buddy lix1 generate ca --cn rtbrick-lab --org rtbrick --ou devops
```
generates
* ca.crt
* ca.key
<!-- end_slide -->

Generate a server certificate signed by the root ca of the organization
===

```bash +exec  
rtb-buddy lix1 generate cert \
          --cn ufi12 --org rtbrick --ou devop \
          --crt ufi12.crt --crt-key ufi12.key \
          --ca-crt ca.crt --ca-crt-key ca.key
```  
generates
* ufi12.crt
* ufi12.key
<!-- end_slide -->

Generate a root ca for client certificate
===
```bash +exec  
rtb-buddy lix1 generate ca \
          --cn rtbrick-lab --org rtbrick --ou devops \
          --ca-crt client-ca.crt --ca-crt-key client-ca.key  
```
generates
* client-ca.crt
* client-ca.key
<!-- end_slide -->

Generate a client1 certificate signed by the client root ca
===
```bash +exec  
rtb-buddy lix1 generate cert \
          --cn client1 --org rtbrick --ou devops \
          --ca-crt client-ca.crt --ca-crt-key client-ca.key \
          --crt client1.crt --crt-key client1.key
```
generates
* client1.crt
* client1.key
<!-- end_slide -->

Generate a set command for the server certificate
===
```bash +exec
rtb-buddy rbfs lix1 server certificate \
          --cert ufi12.crt --cert-key ufi12.key \
          | tee >(pbcopy)
```
<!-- end_slide -->

Generate a set command for the client root certificate
===
```bash +exec
rtb-buddy rbfs lix1 server client-ca \
          --cert client-ca.crt \
          | tee >(pbcopy)
```
<!-- end_slide -->

LIX1 Ping  
===
===
```bash +exec
rtb-buddy rbfs lix1 ping \
          --cert client1.crt --cert-key client1.key \
          --insecure \
          ufi12.q2a.u38.r1.blr.rtbrick.net
```
<!-- end_slide -->

Get the config via restconf
===
```bash +exec
rtb-buddy rbfs config restconf get \
          -p "rtbrick-config:lawful-intercept" ufi12.q2a.u38.r1.blr.rtbrick.net \
          -o law.json
```  
<!-- end_slide -->

Put the config via restconf  
===
```bash +exec
rtb-buddy rbfs config restconf put \
          -p "rtbrick-config:lawful-intercept" ufi12.q2a.u38.r1.blr.rtbrick.net \
          -f law.json
```
<!-- end_slide -->


Thanx!
===

```go {6} +exec +line_numbers
package main

import "fmt"

func main() {
	fmt.Println("The end?")
}
```
<!-- end_slide -->

Topology Manager: Release Topology
===

```bash +exec
rtb-test tm release --id f23a1a4a-fc03-47af-b29a-cfa4769c2295
```