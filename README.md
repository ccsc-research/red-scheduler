# Redundant Packet Scheduling  by Uncorrelated Paths

## Background of MPTCP

Multipath TCP (MPTCP) is an extension to TCP in order to use simultaneously multiple paths. The development of this protocol in the Linux kernel is performed in http://github.com/multipath-tcp/mptcp.

## About the red-scheduler for MPTCP

This redundant scheduler is based on the redundant scheduler of MPTCP. The redundant scheduler sends the data replicated through all the active subflows available. The data is not replicated through backup subflows, which are only used in case of requiring retransmissions.

 Similarly, the red-scheduler replicates data through active subflows, but only through node-disjointed ones. The scheduler calculate a correlation degree between different subflows and prioritize the use of subflows with lower correlation degrees. This way, the scheduler helps to avoid the use of subflows that share the same bottleneck.

This scheduler offers  an improvement in performance on heterogeneous networks scenários.

## Usage

1. Verify hat you are using the red-scheduler for MPTCP.

```bash
~# sysctl net.mptcp.mptcp_scheduler  
net.mptcp.mptcp_scheduler = red
```

2. If not, configure MPTCP with the redundant scheduler. Alternatively, you can configure /etc/sysctl.conf to use this scheduler on every reboot.

```bash
~# sysctl net.mptcp.mptcp_scheduler=red  
net.mptcp.mptcp_scheduler = red
```