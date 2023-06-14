# XDP_Stateful_Load_Balancer
## Introduction
The bulk of the eBPF/XDP code borrows from Liz Rice's sample eBPF load balancer from scratch, https://github.com/lizrice/lb-from-scratch. Our contribution is to provide some basic stateful elements for it to redirect packets belonging to the same TCP connection consistently.
* A forward table to send the traffic of a TCP connection toward a chosen backend server via DNAT.
* A return table to bring the traffic of a TCP connection back to the requesting client via SNAT.
## Build the load balancer
The whole end-to-end set up is to be done in the Killercoda online lab, https://killercoda.com/. The simple load balancer wil be hardcoded to dispatch requests randomly to two backend servers at known IP and MAC addresses.
1. Pull a pre-built eBPF/XDP ready docker to run a container as the platform of the load balancer.
```
docker run -d --privileged --name simplelb -h simplelb snpsuen/ebpfxdp:v05
docker exec -it simplelb bash
```
2. Download this repo, XDP_Stateful_Load_Balancer.
```
cd /var/tmp
git clone https://github.com/snpsuen/XDP_Stateful_Load_Balancer.git
```
3. Build and attach the load balancer to eth0.
```
cd XDP*
make
ls /sys/fs/bpf
ip addr show
```
4. Open a terminal to the host of the container and display the on-going eBPF/XDP kernel traces in real time.
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Deploy backend servers and client
1. Run a pair of backend servers on the nginx hello docker.
```
docker run -d --name backend-A -h backend-A nginxdemos/hello:plain-text
docker run -d --name backend-B -h backend-B nginxdemos/hello:plain-text
```
2. Run a curl client container on the curlimages docker.
```
docker run -d --name curlclient -h curlclient curlimages/curl:latest sleep infinity
```

## Test it out
The load balancer is hardcoded to the IP 172.17.0.2.
1. Issue a curl command from the curl client to the load balancer in a loop.
```
while true
do
curl -s http://172.17.0.2
sleep 3
echo ""
done
```
Expect to receive replies randomly from backend-A, 172.17.0.3 or backend-B, 172.17.0.4.











