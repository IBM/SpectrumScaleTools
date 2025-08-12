Changelog:


- 1.0:
    - Initial release.

- 1.1:
    - Added NSD latency
    - Rx, Tx and retransmit stats
    - Added hosts as parameter
    - PEP8 compliant
    - Minor cosmetic fixes

- 1.2:
    - hosts.json can now we generated from cli input
    - moved from net-tools to iproute and added check for it

- 1.3
    - Initial implementation to run on both python3 and python2

- 1.4
    - Added check for rare (not manage to reproduce in lab) case where nsdperf fails to generate JSON

- 1.5
    - Initial implementation of RDMA throughput tests with nsdperf backend
    - Changed minimum number of hosts from 4 to 2
    - Changed maximum number of nodes from 32 to 64
    - Added option to bypass RPM SW checks
    - Minor cosmetic changes

- 1.6
    - Added support for RHEL 8.0 and RHEL 7.7
    - Minor cosmetic changes

- 1.7
    - More accurate RDMA NSD latency calculation
    - Added check for POSIX ACL of needed files
    - Add warning about RDMA ports UP state as reported by ibdev2netdev
    - Minor cosmetic changes

- 1.8
    - Lower severity of ICMP latency results when using RDMA
    - Added check for firewalld
    - Added LogLevel=error for ssh connections to ignore banners
    - Minor cosmetic changes

- 1.9
    - Fixed issue of nsdperf that made NSD latencies show much bigger than real on x86_64 systems

- 1.10
    - Fixed issue with two nodes test on python3. New min number of nodes is 3 (STG Defect 241194)
    - Mitigated issue of extra SSH lines that messed up the nsdperf wrapper on a corner case of ssh host keys (STG Defect 241193)

- 1.11
    - Sort the IPs for latency test
    - Moved to distro for Python 3 as dist() and linux_distribution() functions are deprecated in Python 3.5

- 1.12
    - Issue with RDMA tests and RHEL 8.1 or higher
    - Added saved CSV file of results for comparison
    - Changed minimum number of nodes to two
- 1.13
    - Fixed issue with 2 nodes
    - Added CentOS 7.8 and 8.2
- 1.14
    - Re-added severity of ICMP latencies for RDMA test mode that were taken away on 1.8. But double the KPI on RDMA for ICMP latency
    - Add a check for all PATH for binaries
    - Added CentOS 7.9 and 8.3
    - Added RHEL 7.9 and 8.3
    - Removed CentOS 7.5 and 8.0
    - Removed RHEL 7.5 and 8.0
- 1.15
    - Fix RDMA checks on ibutils ibdev2net

- 1.16
    - Remove hardcoded path for ibdev2netdev

- 1.17
    - Add RHEL 8.4 and 8.5
    - Fixed issue with difference of 'ip -s link' between RHEL8.3 and RHEL8.5.

- 1.18
    - Support RHEL 8.6
    - Support Roce on s390.

- 1.19
    - Support RHEL 9.0

- 1.20
    - Support RHEL 8.7/9.1
- 1.21
    - Removed options: --latency, --throughput
    - Added options: --thread-number, --parallel, --buffer-size, --socket-size
- 1.30
    - Removed OS version check, using Linux kernel version check instead.
    - Meraged packages_*.json to packages.json.
    - Refactored functions and messages.
- 1.31
    - Upgraded nsdperf to include the following improvements/bug fixes:
        - Fixed race condition in RdmaDevice::createCQ()
        - Fixed log message when posting new RDMA receive work requests.
        - Fixed "handleCQEvent: error" error messages on sub-test completion
        when RDMA SEND is enabled ("rdma all").
        - Support RDMA Connection Manager environments where multiple IP
        addresses/aliases are configured for a RDMA adapter port.
        - Fix compiler warnings.
