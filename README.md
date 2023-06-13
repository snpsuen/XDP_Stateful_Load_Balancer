# XDP_Stateful_Load_Balancer
## Introduction
The eBPF/XDP code borrows mainly from Liz Rice's sample eBPF load balancer from scratch, https://github.com/lizrice/lb-from-scratch. Our contribution is to provide some stateful element for it to redirect packets belonging to the same TCP connection consistently.
