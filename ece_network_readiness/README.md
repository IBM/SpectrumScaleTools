This tool uses fping and nsdperf to run test agianst multiple hosts and presents the results in a way that is easy to interpret. compares the test results with Key Performance Indicators (KPI) and determines if the network was ready to run IBM Storage Scale Erasure Code Edition.

**NOTE:**  Test instance launched by this tool may take a long time, depends on the number of hosts. This tool will display an estimated time consumption at startup. It is recommended to run instance under session of screen or tmux.

**WARNING:** Running this tool would seriously affect network traffic. This tool comes with no warranty of any kind. Do not use it against any production environment.

**RHEL 8.x Platform**
RHEL 8.x does not define default link of /usr/bin/python. Use below command to link default python version to it:

*alternatives --config python*

You can choose either python2 or python3 as default python version. Both of them are supported by this tool.

**Dependent Software**

* gcc-c++
* psmisc
* fping
* python3-distro if use Python3

This tool requires the software installed as RPM package. If you do install above software using different method, run this tool with option: ***--rpm-check-disabled***.
The tool would quit if dependent software was not installed even though you have disabled the check.

gcc-c++ and psmisc can be found from OS image file.

The fping package can be found from [GITHUB](https://github.com/schweikert/fping), [EPEL](https://fedoraproject.org/wiki/EPEL), [RPMFIND](http://rpmfind.net/linux/rpm2html/search.php?query=fping) or somewhere else.

Remarks:

  - The launcher host of this tool must be a member of the cluster.
  - This tool runs on RedHat Enterprise Linux 7.5 or newer, on x86_64 and ppc64le architectures.
  - SSH root passwordless access must be configured from the launcher to all hosts that participate in the test.
  - The minimum value of fping count for a valid certification test must be greater than or equal to 500(default).
  - The minimum value of nsdperf test time for a valid certification test must be greater than or equal to 1200(default) seconds.
  - The number of hosts must be between 2 and 64. Contact IBM if need to run on more hosts.
  - This tool would generate a log folder in current directory with raw data for future comparisons.
  - This tool would return 0 if all tests were passed, else, return an integer which is greater than 0.
  - If use TCP protocol, port 6668 must be idle on all hosts before launch this tool.
  - If use TCP protocol, the IP addresses followed --hosts must be in GPFS daemon network according the installation plan.
  - Firewalld must not be active when this tool is running.
  - This tool must be run on local filesystem of OS.
  - If use RDMA protocol, all Mellanox ports must be in Infiniband mode and have the same logical device names.
  - If use RDMA protocol, the IP addresses followed --hosts should be in cluster admin network according the installation plan.
  - If use RDMA protocol, network device must be Up as shown by command [*ibdev2netdev*](https://community.mellanox.com/s/article/ibdev2netdev).
  - On RedHat Enterprise Linux 8 platforms, one can select default python version with command: *alternatives --config python*.
  - If set a bond device based on RDMA devices, be sure that ''ibdev2netdev'' showed ib name instead of bond name.

Usage:
```
# python3 koet.py -h
usage: koet.py [-h] [--hosts HOSTS_CSV] [-s] [-c COUNT] [-t TIME] [-r THREAD]
               [-p PARALLEL] [-b BUFFSIZE] [-o SOCKSIZE] [--rdma PORTS_CSV]
               [--roce PORTS_CSV] [--rpm-check-disabled] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --hosts HOSTS_CSV     IPv4 addresses in CSV format. E.g., IP0,IP1,IP2,IP3
  -s, --save-hosts      [Over]write hosts.json with IP addresses that passed
                        the check and followed option: --hosts
  -c COUNT, --fping-count COUNT
                        count of request packets to send to each target. The
                        minimum value can be set to 2 packets for quick test.
                        For certification, it is at least 500 packets
  -t TIME, --ttime-per-instance TIME
                        test time per nsdperf instance with unit sec. The
                        minimum value can be set to 10 sec for quick test. For
                        certification, it is at least 1200 sec
  -r THREAD, --thread-number THREAD
                        test thread number per nsdperf instance on client. The
                        minimum value is 1 and the maximum value is 4096. For
                        certification, it is 32
  -p PARALLEL, --parallel PARALLEL
                        parallel socket connections of nsdperf per instance.
                        The minimum value is 1 and the maximum value is 8191.
                        Default value is 2
  -b BUFFSIZE, --buffer-size BUFFSIZE
                        buffer size for each I/O of nsdperf with unit bytes.
                        The minimum value is 4096 bytes and the maximum value
                        is 16777216 bytes. For certification, it is 2097152
                        bytes
  -o SOCKSIZE, --socket-size SOCKSIZE
                        maximum TCP socket send and receive buffer size with
                        unit bytes. 0 means the system default setting and the
                        maximum value is 104857600 bytes. This tool would set
                        the socket size to the I/O buffer size if socket size
                        was not specified explicitly
  --rdma PORTS_CSV      Enable RDMA check and assign ports in CSV format.
                        E.g., ib0,ib1. Use logical device name rather than mlx
                        name
  --roce PORTS_CSV      Enable RoCE check and assign ports in CSV format.
                        E.g., eth0,eth1. Use logical device name
  --rpm-check-disabled  Disable dependent rpm package check. Use this option
                        only if you are sure that all dependent packages have
                        been installed
  -v, --version         show program's version number and exit
```

Typically launch this tool with TCP protocol. Use GPFS daemon IP addresses then save them to hosts.json for future runs.
```
# python3 koet.py --hosts 10.10.12.92,10.10.12.93,10.10.12.94,10.10.12.95 --save-hosts
```

To launch this tool with hosts.json that already populated by above example:
```
# python3 koet.py
```

To run RDMA test with ib0 and ib1 on all hosts, in condition that hosts.json has already been populated with admin IP addresses.
```
# python3 koet.py --rdma ib0,ib1
```

KNOWN ISSUES:
  - RoCE protocol test does not supported at present.
  - If encounter problem please contact IBM.


An example with default option using populated hosts.json:
```
# python3 koet.py

Welcome to Network Readiness 1.21

The purpose of the tool is to obtain network metrics of a number of nodes then compare them with certain KPIs
Please access to https://github.com/IBM/SpectrumScaleTools to get required versions and report issues if necessary

Prerequisite:
  Remote root passwordless ssh between all all nodes must be configured

NOTE:
  This tool comes with absolutely no warranty of any kind. Use it at your own risk.
  The latency and throughput numbers shown by this tool are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload's performance number that run on it.

JSON files versions:
    supported OS:     1.11
    packages:         1.1
    packages RDMA:    1.0
    packages RoCE:    1.0

To certify the environment:
The average latency KPI is 1.0 msec
The maximum latency KPI is 2.0 mesc
The standard deviation latency KPI is 0.33 mesc
The throughput KPI is 2000 MB/sec

INFO: The fping count per instance needs at least 500 request packets. Current setting is 500 packets
INFO: The nsdperf needs at least 1200 sec test time per instance. Current setting is 1200 sec
INFO: The nsdperf needs 32 test thread per instance. Current setting is 32
INFO: The nsdperf needs 2097152 bytes buffer size. Current setting is 2097152 bytes

INFO: The total time consumption according to above paramters is ~135 minutes

Do you want to continue? (y/n):
```

Warning messages would be printed if gave unreasonable options:
```
# python3 koet.py -c 100 -t 120 -r 16 -b 4096

Welcome to Network Readiness 1.21

The purpose of the tool is to obtain network metrics of a number of nodes then compare them with certain KPIs
Please access to https://github.com/IBM/SpectrumScaleTools to get required versions and report issues if necessary

Prerequisite:
  Remote root passwordless ssh between all all nodes must be configured

NOTE:
  This tool comes with absolutely no warranty of any kind. Use it at your own risk.
  The latency and throughput numbers shown by this tool are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload's performance number that run on it.

JSON files versions:
    supported OS:     1.11
    packages:         1.1
    packages RDMA:    1.0
    packages RoCE:    1.0

To certify the environment:
The average latency KPI is 1.0 msec
The maximum latency KPI is 2.0 mesc
The standard deviation latency KPI is 0.33 mesc
The throughput KPI is 2000 MB/sec

WARNING: The fping count per instance needs at least 500 request packets. Current setting is 100 packets
WARNING: The nsdperf needs at least 1200 sec test time per instance. Current setting is 120 sec
WARNING: The nsdperf needs 32 test thread per instance. Current setting is 16
WARNING: The nsdperf needs 2097152 bytes buffer size. Current setting is 4096 bytes

INFO: The total time consumption according to above paramters is ~19 minutes

Do you want to continue? (y/n):
```

Output from a successful example with TCP/IP.
```
OK: SSH with node 10.168.2.101 works
OK: SSH with node 10.168.2.101 works with strict host key checks
OK: SSH with node 10.168.2.105 works
OK: SSH with node 10.168.2.105 works with strict host key checks
OK: SSH with node 10.168.2.109 works
OK: SSH with node 10.168.2.109 works with strict host key checks
OK: SSH with node 10.168.2.113 works
OK: SSH with node 10.168.2.113 works with strict host key checks

Pre-flight generic checks:
OK: on host 10.168.2.101 the fping installation status is as expected
OK: on host 10.168.2.101 the gcc-c++ installation status is as expected
OK: on host 10.168.2.101 the psmisc installation status is as expected
OK: on host 10.168.2.101 the iproute installation status is as expected
OK: on host 10.168.2.105 the fping installation status is as expected
OK: on host 10.168.2.105 the gcc-c++ installation status is as expected
OK: on host 10.168.2.105 the psmisc installation status is as expected
OK: on host 10.168.2.105 the iproute installation status is as expected
OK: on host 10.168.2.109 the fping installation status is as expected
OK: on host 10.168.2.109 the gcc-c++ installation status is as expected
OK: on host 10.168.2.109 the psmisc installation status is as expected
OK: on host 10.168.2.109 the iproute installation status is as expected
OK: on host 10.168.2.113 the fping installation status is as expected
OK: on host 10.168.2.113 the gcc-c++ installation status is as expected
OK: on host 10.168.2.113 the psmisc installation status is as expected
OK: on host 10.168.2.113 the iproute installation status is as expected
OK: on host 10.168.2.101 the firewalld service is not running
OK: on host 10.168.2.105 the firewalld service is not running
OK: on host 10.168.2.109 the firewalld service is not running
OK: on host 10.168.2.113 the firewalld service is not running
OK: on host 10.168.2.101 TCP port 6668 seems to be free
OK: on host 10.168.2.105 TCP port 6668 seems to be free
OK: on host 10.168.2.109 TCP port 6668 seems to be free
OK: on host 10.168.2.113 TCP port 6668 seems to be free

Creating log dir on hosts:
OK: on host 10.168.2.101 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-29_22-07-09 has been created
OK: on host 10.168.2.105 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-29_22-07-09 has been created
OK: on host 10.168.2.109 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-29_22-07-09 has been created
OK: on host 10.168.2.113 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-29_22-07-09 has been created

Starting ping run from 10.168.2.101 to all nodes
Ping run from 10.168.2.101 to all nodes completed

Starting ping run from 10.168.2.105 to all nodes
Ping run from 10.168.2.105 to all nodes completed

Starting ping run from 10.168.2.109 to all nodes
Ping run from 10.168.2.109 to all nodes completed

Starting ping run from 10.168.2.113 to all nodes
Ping run from 10.168.2.113 to all nodes completed

Starting throughput tests. Please be patient.

Start throughput run from 10.168.2.101 to all nodes
Completed throughput run from 10.168.2.101 to all nodes

Start throughput run from 10.168.2.105 to all nodes
Completed throughput run from 10.168.2.105 to all nodes

Start throughput run from 10.168.2.109 to all nodes
Completed throughput run from 10.168.2.109 to all nodes

Start throughput run from 10.168.2.113 to all nodes
Completed throughput run from 10.168.2.113 to all nodes

Starting many to many nodes throughput test
Completed many to many nodes throughput test

Results for ICMP latency test 1:n
OK: on host 10.168.2.101 the 1:n average ICMP latency is 0.13 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.101 the 1:n maximum ICMP latency is 0.25 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.101 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.101 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.105 the 1:n average ICMP latency is 0.15 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.105 the 1:n maximum ICMP latency is 0.26 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.105 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.105 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.109 the 1:n average ICMP latency is 0.15 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.109 the 1:n maximum ICMP latency is 0.24 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.109 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.109 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.113 the 1:n average ICMP latency is 0.14 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.113 the 1:n maximum ICMP latency is 0.24 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.113 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.113 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

Results for throughput test
OK: on host 10.168.2.101 the throughput test result is 8670 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.105 the throughput test result is 8430 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.109 the throughput test result is 9220 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.113 the throughput test result is 9050 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host all at the same time the throughput test result is 13500 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: the difference of throughput between maximum and minimum values is 8.57%, which is less than 20% defined on the KPI

The following metrics are not part of the KPI and are shown for informational purposes only
INFO: The maximum throughput value is 9220.0
INFO: The minimum throughput value is 8430.0
INFO: The mean throughput value is 8842.5
INFO: The standard deviation throughput value is 358.46
INFO: The average NSD latency for 10.168.2.101 is 1.6305 msec
INFO: The average NSD latency for 10.168.2.105 is 1.56452 msec
INFO: The average NSD latency for 10.168.2.109 is 1.50673 msec
INFO: The average NSD latency for 10.168.2.113 is 1.52741 msec
INFO: The average NSD latency for all at the same time is 1.44246 msec
INFO: The standard deviation of NSD latency for 10.168.2.101 is 0.560723 msec
INFO: The standard deviation of NSD latency for 10.168.2.105 is 0.574662 msec
INFO: The standard deviation of NSD latency for 10.168.2.109 is 0.5333 msec
INFO: The standard deviation of NSD latency for 10.168.2.113 is 0.54301 msec
INFO: The standard deviation of NSD latency for all at the same time is 0.503492 msec
INFO: The packet Rx error count for throughput test on 10.168.2.101 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.105 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.109 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.113 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.101 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.105 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.109 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.113 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.101 is equal to 91 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.105 is equal to 3 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.109 is equal to 7 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.113 is equal to 6 packet[s]
INFO: The packet Rx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test many to many is equal to 24 packet[s]
INFO: CSV file with throughput information can be found at /u/czbj/developing_ece_network_readiness/log/2023-08-29_22-07-09/throughput.csv

The summary of this run:

        The 1:n ICMP average latency was successful in all nodes
        The 1:n throughput test was successful in all nodes

OK: All tests have passed
OK: You can proceed to the next step
```

Output from a successful example with RDMA.
```
OK: SSH with node 10.168.2.101 works
OK: SSH with node 10.168.2.101 works with strict host key checks
OK: SSH with node 10.168.2.105 works
OK: SSH with node 10.168.2.105 works with strict host key checks
OK: SSH with node 10.168.2.109 works
OK: SSH with node 10.168.2.109 works with strict host key checks
OK: SSH with node 10.168.2.113 works
OK: SSH with node 10.168.2.113 works with strict host key checks

Pre-flight generic checks:
OK: on host 10.168.2.101 the fping installation status is as expected
OK: on host 10.168.2.101 the gcc-c++ installation status is as expected
OK: on host 10.168.2.101 the psmisc installation status is as expected
OK: on host 10.168.2.101 the iproute installation status is as expected
OK: on host 10.168.2.105 the fping installation status is as expected
OK: on host 10.168.2.105 the gcc-c++ installation status is as expected
OK: on host 10.168.2.105 the psmisc installation status is as expected
OK: on host 10.168.2.105 the iproute installation status is as expected
OK: on host 10.168.2.109 the fping installation status is as expected
OK: on host 10.168.2.109 the gcc-c++ installation status is as expected
OK: on host 10.168.2.109 the psmisc installation status is as expected
OK: on host 10.168.2.109 the iproute installation status is as expected
OK: on host 10.168.2.113 the fping installation status is as expected
OK: on host 10.168.2.113 the gcc-c++ installation status is as expected
OK: on host 10.168.2.113 the psmisc installation status is as expected
OK: on host 10.168.2.113 the iproute installation status is as expected
OK: on host 10.168.2.101 the firewalld service is not running
OK: on host 10.168.2.105 the firewalld service is not running
OK: on host 10.168.2.109 the firewalld service is not running
OK: on host 10.168.2.113 the firewalld service is not running
OK: on host 10.168.2.101 TCP port 6668 seems to be free
OK: on host 10.168.2.105 TCP port 6668 seems to be free
OK: on host 10.168.2.109 TCP port 6668 seems to be free
OK: on host 10.168.2.113 TCP port 6668 seems to be free

Pre-flight RDMA checks:
OK: on host 10.168.2.101 the librdmacm installation status is as expected
OK: on host 10.168.2.101 the librdmacm-utils installation status is as expected
OK: on host 10.168.2.101 the rdma-core-devel installation status is as expected
OK: on host 10.168.2.101 the ibutils2 installation status is as expected
OK: on host 10.168.2.105 the librdmacm installation status is as expected
OK: on host 10.168.2.105 the librdmacm-utils installation status is as expected
OK: on host 10.168.2.105 the rdma-core-devel installation status is as expected
OK: on host 10.168.2.105 the ibutils2 installation status is as expected
OK: on host 10.168.2.109 the librdmacm installation status is as expected
OK: on host 10.168.2.109 the librdmacm-utils installation status is as expected
OK: on host 10.168.2.109 the rdma-core-devel installation status is as expected
OK: on host 10.168.2.109 the ibutils2 installation status is as expected
OK: on host 10.168.2.113 the librdmacm installation status is as expected
OK: on host 10.168.2.113 the librdmacm-utils installation status is as expected
OK: on host 10.168.2.113 the rdma-core-devel installation status is as expected
OK: on host 10.168.2.113 the ibutils2 installation status is as expected
OK: on host 10.168.2.101 the file ibdev2netdev exists
OK: on host 10.168.2.101 the file ibstat exists
OK: on host 10.168.2.105 the file ibdev2netdev exists
OK: on host 10.168.2.105 the file ibstat exists
OK: on host 10.168.2.109 the file ibdev2netdev exists
OK: on host 10.168.2.109 the file ibstat exists
OK: on host 10.168.2.113 the file ibdev2netdev exists
OK: on host 10.168.2.113 the file ibstat exists
OK: on host 10.168.2.101 the RDMA port ib0 is on UP state
OK: on host 10.168.2.101 the RDMA port ib1 is on UP state
OK: on host 10.168.2.105 the RDMA port ib0 is on UP state
OK: on host 10.168.2.105 the RDMA port ib1 is on UP state
OK: on host 10.168.2.109 the RDMA port ib0 is on UP state
OK: on host 10.168.2.109 the RDMA port ib1 is on UP state
OK: on host 10.168.2.113 the RDMA port ib0 is on UP state
OK: on host 10.168.2.113 the RDMA port ib1 is on UP state
OK: on host 10.168.2.101 the RDMA port ib0 is CA mlx5_0/1
OK: on host 10.168.2.101 the RDMA port ib1 is CA mlx5_1/1
OK: on host 10.168.2.105 the RDMA port ib0 is CA mlx5_0/1
OK: on host 10.168.2.105 the RDMA port ib1 is CA mlx5_1/1
OK: on host 10.168.2.109 the RDMA port ib0 is CA mlx5_0/1
OK: on host 10.168.2.109 the RDMA port ib1 is CA mlx5_1/1
OK: on host 10.168.2.113 the RDMA port ib0 is CA mlx5_0/1
OK: on host 10.168.2.113 the RDMA port ib1 is CA mlx5_1/1
OK: on host 10.168.2.101 Mellanox ports  ib0 on Ethernet mode are supported
OK: on host 10.168.2.101 Mellanox ports  ib1 on Ethernet mode are supported
OK: on host 10.168.2.105 Mellanox ports  ib0 on Ethernet mode are supported
OK: on host 10.168.2.105 Mellanox ports  ib1 on Ethernet mode are supported
OK: on host 10.168.2.109 Mellanox ports  ib0 on Ethernet mode are supported
OK: on host 10.168.2.109 Mellanox ports  ib1 on Ethernet mode are supported
OK: on host 10.168.2.113 Mellanox ports  ib0 on Ethernet mode are supported
OK: on host 10.168.2.113 Mellanox ports  ib1 on Ethernet mode are supported
OK: all RDMA ports are up on all nodes

Creating log dir on hosts:
OK: on host 10.168.2.101 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-30_01-39-53 has been created
OK: on host 10.168.2.105 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-30_01-39-53 has been created
OK: on host 10.168.2.109 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-30_01-39-53 has been created
OK: on host 10.168.2.113 logdir /u/czbj/developing_ece_network_readiness/log/2023-08-30_01-39-53 has been created

Starting ping run from 10.168.2.101 to all nodes
Ping run from 10.168.2.101 to all nodes completed

Starting ping run from 10.168.2.105 to all nodes
Ping run from 10.168.2.105 to all nodes completed

Starting ping run from 10.168.2.109 to all nodes
Ping run from 10.168.2.109 to all nodes completed

Starting ping run from 10.168.2.113 to all nodes
Ping run from 10.168.2.113 to all nodes completed

Starting throughput tests. Please be patient.

Start throughput run from 10.168.2.101 to all nodes
Completed throughput run from 10.168.2.101 to all nodes

Start throughput run from 10.168.2.105 to all nodes
Completed throughput run from 10.168.2.105 to all nodes

Start throughput run from 10.168.2.109 to all nodes
Completed throughput run from 10.168.2.109 to all nodes

Start throughput run from 10.168.2.113 to all nodes
Completed throughput run from 10.168.2.113 to all nodes

Starting many to many nodes throughput test
Completed many to many nodes throughput test

Results for ICMP latency test 1:n
OK: on host 10.168.2.101 the 1:n average ICMP latency is 0.16 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.101 the 1:n maximum ICMP latency is 0.25 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.101 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.101 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.105 the 1:n average ICMP latency is 0.16 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.105 the 1:n maximum ICMP latency is 0.25 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.105 the 1:n minimum ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.105 the 1:n standard deviation of ICMP latency is 0.00 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.109 the 1:n average ICMP latency is 0.14 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.109 the 1:n maximum ICMP latency is 0.27 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.109 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.109 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.168.2.113 the 1:n average ICMP latency is 0.14 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.113 the 1:n maximum ICMP latency is 0.26 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.168.2.113 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.168.2.113 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

Results for throughput test
OK: on host 10.168.2.101 the throughput test result is 24000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.105 the throughput test result is 24000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.109 the throughput test result is 24500 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 10.168.2.113 the throughput test result is 24600 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host all at the same time the throughput test result is 47800 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: the difference of throughput between maximum and minimum values is 2.44%, which is less than 20% defined on the KPI

The following metrics are not part of the KPI and are shown for informational purposes only
INFO: The maximum throughput value is 24600.0
INFO: The minimum throughput value is 24000.0
INFO: The mean throughput value is 24275.0
INFO: The standard deviation throughput value is 320.16
INFO: The average NSD latency for 10.168.2.101 is 2.70798 msec
INFO: The average NSD latency for 10.168.2.105 is 2.69019 msec
INFO: The average NSD latency for 10.168.2.109 is 2.63669 msec
INFO: The average NSD latency for 10.168.2.113 is 2.62044 msec
INFO: The average NSD latency for all at the same time is 2.32364 msec
INFO: The standard deviation of NSD latency for 10.168.2.101 is 0.569844 msec
INFO: The standard deviation of NSD latency for 10.168.2.105 is 0.560671 msec
INFO: The standard deviation of NSD latency for 10.168.2.109 is 0.559436 msec
INFO: The standard deviation of NSD latency for 10.168.2.113 is 0.540392 msec
INFO: The standard deviation of NSD latency for all at the same time is 0.600218 msec
INFO: The packet Rx error count for throughput test on 10.168.2.101 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.105 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.109 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.168.2.113 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.101 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.105 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.109 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.168.2.113 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.101 is equal to 180 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.105 is equal to 1 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.109 is equal to 1 packet[s]
INFO: The packet retransmit count for throughput test on 10.168.2.113 is equal to 1 packet[s]
INFO: The packet Rx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test many to many is equal to 28 packet[s]
INFO: CSV file with throughput information can be found at /u/czbj/developing_ece_network_readiness/log/2023-08-30_01-39-53/throughput.csv

The summary of this run:

        The 1:n ICMP average latency was successful in all nodes
        The 1:n throughput test was successful in all nodes

OK: All tests have passed
OK: You can proceed to the next step
```
