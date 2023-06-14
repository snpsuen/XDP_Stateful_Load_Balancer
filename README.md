# XDP_Stateful_Load_Balancer
## Introduction
The bulk of the eBPF/XDP code borrows from Liz Rice's sample eBPF load balancer from scratch, https://github.com/lizrice/lb-from-scratch. Our contribution is to provide some basic stateful elements for it to redirect packets belonging to the same TCP connection consistently
* A forward table to send the traffic of a TCP connection toward a chosen backend server via DNAT.
* A return table to bring the traffic of a TCP connection back to the requesting client via SNAT.
## Build the load balancer
1. Pull an eBPF/XDP ready docker to run a container as the platform of the load balancer.
```
docker run -d --privileged --name simplelb -h simplelb snpsuen/ebpfxdp:v05
docker exec -it simplelb bash
```
2. Download this repo, XDP_Stateful_Load_Balancer.


