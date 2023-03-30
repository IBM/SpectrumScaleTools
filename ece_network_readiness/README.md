This tool will run a network test across multiple nodes and compare the results against IBM Spectrum Scale Key Performance Indicators (KPI).
This tool attempts to hide much of the complexity of running network measurement tools, and present the results in an easy to interpret way.

**NOTE:** This tool would run for a long time, depending on the number of hosts to be tested. It estimates and shows the total runtime before the first interaction.

**WARNING:** This is a network stress tool. Running this tool would seriously affect network traffic. This tool, as stated on the license, it comes with no warranty of any kind.

**RHEL 8.x Platform**
RHEL 8.x does not define default link of /usr/bin/python. Use below command to link default python version to it:

*alternatives --config python*

You can choose either python2 or python3 as default python version. Both of them are supported by this tool.

**Dependent Software**

* gcc-c++
* psmisc
* fping
* python3-distro if use Python3

This tool requires the software installed as RPM package. If you do install above software using different method, run this tool with option: ***--rpm_check_disabled***.
The tool would quit if dependent software was not installed even though you have disabled the check.

gcc-c++ and psmisc can be found from OS image file.

The fping package can be found from [EPEL](https://fedoraproject.org/wiki/EPEL), [RPMFIND](http://rpmfind.net/linux/rpm2html/search.php?query=fping) or somewhere else.

Remarks:

  - The launcher host of this tool must be a member of the cluster.
  - Run this tool under *screen* or *tmux* in case of terminal disconnection. Do not use nohup since it would not spawn subprocesses correclty.
  - This tool runs on RedHat Enterprise Linux 7.5 or newer, on x86_64 and ppc64le architectures.
  - SSH root passwordless access must be configured from the launcher to all hosts that participate in the test.
  - The minimum FPING_COUNT value for a valid certification test must be greater than or equal to 500(default).
  - The minimum PERF_RUNTIME value for a valid certification test must be greater than or equal to 1200(default) seconds.
  - The number of hosts must be between 2 and 64. Contact IBM if need to run on more hosts.
  - This tool would generate a log folder in current directory with raw data for future comparisons.
  - This tool would return 0 if all tests were passed, else, return an integer which is greater than 0.
  - If use TCP protocol, port 6668 must be idle on all hosts before launch this tool.
  - If use TCP protocol, the IP addresses followed --hosts must be in daemon network of the cluster.
  - Firewalld must not be active when this tool is running.
  - This tool must be run on local filesystem of OS.
  - If use RDMA protocol, all Mellanox ports must be in Infiniband mode and have the same logical device names.
  - If use RDMA protocol, the IP addresses followed --hosts should be in admin network of the cluster.
  - If use RDMA protocol, network device must be Up as shown by command [*ibdev2netdev*](https://community.mellanox.com/s/article/ibdev2netdev).
  - On RedHat Enterprise Linux 8 platforms, one can select default python version with command: *alternatives --config python*.
  - If set a bond device based on RDMA devices, be sure that ''ibdev2netdev'' showed ib name instead of bond name.


Typically launch this tool with TCP protocol. Use daemon IP addresses then generate hosts.json for future runs:

```shell
# ./koet.py --hosts 10.10.12.92,10.10.12.93,10.10.12.94,10.10.12.95 --save-hosts
```

To launch this tool with hosts.json that already populated by above example:

```shell
# ./koet.py
```

To run RDMA test with ib0 and ib1 on all hosts, with hosts.json already populated with admin IP addresses:

```shell
# ./koet.py --rdma ib0,ib1
```

KNOWN ISSUES:
  - RoCE protocol test does not supported at present.
  - If encounter problem please contact IBM.

TODO:
  - Add an option to load previous test results then compare.

Usage help:
```
# ./koet.py -h
usage: py_ver_koet.py [-h] [--hosts HOSTS_CSV] [--save-hosts] [-c FPING_COUNT]
                      [-r PERF_RUNTIME] [-l KPI_LATENCY] [-t KPI_THROUGHPUT]
                      [--rdma PORTS_CSV] [--roce PORTS_CSV]
                      [--rpm-check-disabled] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --hosts HOSTS_CSV     IPv4 addresses in CSV format. E.g., IP0,IP1,IP2,IP3
  --save-hosts          [Over]write hosts.json with IP addresses that passed
                        the check and followed option: --hosts
  -c FPING_COUNT, --fping-count FPING_COUNT
                        count of fping iteration per host. The interval
                        between each iteration is 1 second. The minimum value
                        can be set to 2. For certification, it is at least 500
  -r PERF_RUNTIME, --perf-runtime PERF_RUNTIME
                        runtime of nsdperf per instance. The minimum value can
                        be set to 10 seconds. For certification, it is at
                        least 1200 seconds
  -l KPI_LATENCY, --latency KPI_LATENCY
                        latency KPI in floating-point format. The maximum
                        required value for certification is 1.0 msec
  -t KPI_THROUGHPUT, --throughput KPI_THROUGHPUT
                        throughput KPI with unit MB/sec. The minimum required
                        value for certification is 2000 MB/sec
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

An example with default option using populated hosts.json:

```
./koet.py

Welcome to KOET, version 1.5

JSON files versions:
	supported OS:		1.2
	packages: 		1.1
	packages RDMA:		1.0

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of KOET is to obtain IPv4 network metrics for a number of nodes.

The latency KPI value of 1.0 msec is good to certify the environment

The fping count value of 500 ping per test and node is good to certify the environment

The throughput value of 2000 MB/sec is good to certify the environment

The performance runtime value of 1200 second per test and node is good to certify the environment

It requires remote ssh passwordless between all nodes for user root already configured

This test run estimation is 336 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload

Do you want to continue? (y/n):
```

You can see the estimated runtime from above output, then consider launching this tool by using *screen* or *tmux*.

If count of fping and runtime of nsdperf are modified, you would see warning messages as follows:

```
# ./koet.py -l 1.5 -c 100 -p 10 -m 100

Welcome to KOET, version 1.2

JSON files versions:
        supported OS:           1.1
        packages:               1.1

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of KOET is to obtain IPv4 network metrics for a number of nodes.

WARNING: The latency KPI value of 1.5 msec is too high to certify the environment

WARNING: The fping count value of 100 pings per test and node is not enough to certify the environment

WARNING: The throughput value of 100 MB/sec is  not enough to certify the environment

WARNING: The performance runtime value of 10 second per test and node is not enough to certify the environment

It requires remote ssh passwordless between all nodes for user root already configured

This test run estimation is 50 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. It is not a storage benchmark.
They do not necessarily reflect that numbers you would see with Spectrum Scale and your particular workload

Do you want to continue? (y/n): y
```

The following output comes an example of a successful run with TCP. 

```
OK: Red Hat Enterprise Linux Server 7.6 is a supported OS for this tool

OK: SSH with node 10.10.12.93 works
OK: SSH with node 10.10.12.92 works
OK: SSH with node 10.10.12.95 works
OK: SSH with node 10.10.12.94 works

Checking packages install status:

OK: on host 10.10.12.93 the psmisc installation status is as expected
OK: on host 10.10.12.93 the fping installation status is as expected
OK: on host 10.10.12.93 the gcc-c++ installation status is as expected
OK: on host 10.10.12.92 the psmisc installation status is as expected
OK: on host 10.10.12.92 the fping installation status is as expected
OK: on host 10.10.12.92 the gcc-c++ installation status is as expected
OK: on host 10.10.12.95 the psmisc installation status is as expected
OK: on host 10.10.12.95 the fping installation status is as expected
OK: on host 10.10.12.95 the gcc-c++ installation status is as expected
OK: on host 10.10.12.94 the psmisc installation status is as expected
OK: on host 10.10.12.94 the fping installation status is as expected
OK: on host 10.10.12.94 the gcc-c++ installation status is as expected
OK: on host 10.10.12.93 TCP port 6668 seems to be free
OK: on host 10.10.12.92 TCP port 6668 seems to be free
OK: on host 10.10.12.95 TCP port 6668 seems to be free
OK: on host 10.10.12.94 TCP port 6668 seems to be free

Starting ping run from 10.10.12.93 to all nodes
Ping run from 10.10.12.93 to all nodes completed

Starting ping run from 10.10.12.92 to all nodes
Ping run from 10.10.12.92 to all nodes completed

Starting ping run from 10.10.12.95 to all nodes
Ping run from 10.10.12.95 to all nodes completed

Starting ping run from 10.10.12.94 to all nodes
Ping run from 10.10.12.94 to all nodes completed

Starting throughput tests. Please be patient.

Starting throughput run from 10.10.12.93 to all nodes
Completed throughput run from 10.10.12.93 to all nodes

Starting throughput run from 10.10.12.92 to all nodes
Completed throughput run from 10.10.12.92 to all nodes

Starting throughput run from 10.10.12.95 to all nodes
Completed throughput run from 10.10.12.95 to all nodes

Starting throughput run from 10.10.12.94 to all nodes
Completed throughput run from 10.10.12.94 to all nodes

Starting many to many nodes throughput test
Completed Many to many nodes throughput test

Results for ICMP latency test 1:n
OK: on host 10.10.12.93 the 1:n average ICMP latency is 0.37 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.93 the 1:n maximum ICMP latency is 0.45 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.10.12.93 the 1:n minimum ICMP latency is 0.31 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.93 the 1:n standard deviation of ICMP latency is 0.02 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.10.12.92 the 1:n average ICMP latency is 0.27 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.92 the 1:n maximum ICMP latency is 0.44 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.10.12.92 the 1:n minimum ICMP latency is 0.17 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.92 the 1:n standard deviation of ICMP latency is 0.09 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.10.12.95 the 1:n average ICMP latency is 0.26 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.95 the 1:n maximum ICMP latency is 0.41 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.10.12.95 the 1:n minimum ICMP latency is 0.13 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.95 the 1:n standard deviation of ICMP latency is 0.08 msec. Which is lower than the KPI of 0.33 msec

OK: on host 10.10.12.94 the 1:n average ICMP latency is 0.26 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.94 the 1:n maximum ICMP latency is 0.44 msec. Which is lower than the KPI of 2.0 msec
OK: on host 10.10.12.94 the 1:n minimum ICMP latency is 0.17 msec. Which is lower than the KPI of 1.0 msec
OK: on host 10.10.12.94 the 1:n standard deviation of ICMP latency is 0.09 msec. Which is lower than the KPI of 0.33 msec

Results for throughput test
OK: on host 10.10.12.93 the throughput test result is 2354 MB/sec. Which is more than the KPI of 2000 MB/sec
OK: on host 10.10.12.92 the throughput test result is 2389 MB/sec. Which is more than the KPI of 2000 MB/sec
OK: on host 10.10.12.95 the throughput test result is 2312 MB/sec. Which is more than the KPI of 2000 MB/sec
OK: on host 10.10.12.94 the throughput test result is 2392 MB/sec. Which is more than the KPI of 2000 MB/sec
OK: the difference of bandwidth between nodes is 10.16% which is less than 20% defined on the KPI

The following metrics are not part of the KPI and are shown for informational purposes only
INFO: The maximum throughput value is 2466.0
INFO: The minimum throughput value is 2312.0
INFO: The mean throughput value is 2385.67
INFO: The standard deviation throughput value is 51.32
INFO: The average NSD latency for 10.10.12.93 is 117.172 msec
INFO: The average NSD latency for 10.10.12.92 is 19.0734 msec
INFO: The average NSD latency for all at the same time is 11.5054 msec
INFO: The average NSD latency for 10.10.12.95 is 16.941 msec
INFO: The average NSD latency for 10.10.12.94 is 16.8137 msec
INFO: The standard deviation of NSD latency for 10.10.12.93 is 5.46121 msec
INFO: The standard deviation of NSD latency for 10.10.12.92 is 18.9215 msec
INFO: The standard deviation of NSD latency for all at the same time is 20.145 msec
INFO: The standard deviation of NSD latency for 10.10.12.95 is 16.8196 msec
INFO: The standard deviation of NSD latency for 10.10.12.94 is 16.8328 msec
INFO: The packet Rx error count for throughput test on 10.10.12.93 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.10.12.92 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.10.12.95 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 10.10.12.94 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.10.12.93 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.10.12.92 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.10.12.95 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 10.10.12.94 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.10.12.93 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.10.12.92 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.10.12.95 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 10.10.12.94 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test many to many is equal to 0 packet[s]

The summary of this run:

        The 1:n fping average latency was successful in all
        The 1:n throughput test was successful in all nodes

OK: All tests had been passed. You can proceed with the next steps
```

And a successful example with RDMA:

```
# ./koet.py --rdma ib0

./koet.py

Welcome to KOET, version 1.5

JSON files versions:
	supported OS:		1.2
	packages: 		1.1
	packages RDMA:		1.0

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of KOET is to obtain IPv4 network metrics for a number of nodes.

The latency KPI value of 1.0 msec is good to certify the environment

The fping count value of 500 ping per test and node is good to certify the environment

The throughput value of 2000 MB/sec is good to certify the environment

The performance runtime value of 1200 second per test and node is good to certify the environment

It requires remote ssh passwordless between all nodes for user root already configured

This test run estimation is 336 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload

Do you want to continue? (y/n): y

OK: Red Hat Enterprise Linux Server 7.6 is a supported OS for this tool

OK: SSH with node 100.168.83.9 works
OK: SSH with node 100.168.83.8 works
OK: SSH with node 100.168.83.3 works
OK: SSH with node 100.168.83.2 works
OK: SSH with node 100.168.83.1 works
OK: SSH with node 100.168.83.7 works
OK: SSH with node 100.168.83.6 works
OK: SSH with node 100.168.83.5 works
OK: SSH with node 100.168.83.10 works
OK: SSH with node 100.168.83.11 works
OK: SSH with node 100.168.83.4 works

Pre-flight generic checks:
OK: on host 100.168.83.9 the iproute installation status is as expected
OK: on host 100.168.83.9 the psmisc installation status is as expected
OK: on host 100.168.83.9 the fping installation status is as expected
OK: on host 100.168.83.9 the gcc-c++ installation status is as expected
OK: on host 100.168.83.8 the iproute installation status is as expected
OK: on host 100.168.83.8 the psmisc installation status is as expected
OK: on host 100.168.83.8 the fping installation status is as expected
OK: on host 100.168.83.8 the gcc-c++ installation status is as expected
OK: on host 100.168.83.3 the iproute installation status is as expected
OK: on host 100.168.83.3 the psmisc installation status is as expected
OK: on host 100.168.83.3 the fping installation status is as expected
OK: on host 100.168.83.3 the gcc-c++ installation status is as expected
OK: on host 100.168.83.2 the iproute installation status is as expected
OK: on host 100.168.83.2 the psmisc installation status is as expected
OK: on host 100.168.83.2 the fping installation status is as expected
OK: on host 100.168.83.2 the gcc-c++ installation status is as expected
OK: on host 100.168.83.1 the iproute installation status is as expected
OK: on host 100.168.83.1 the psmisc installation status is as expected
OK: on host 100.168.83.1 the fping installation status is as expected
OK: on host 100.168.83.1 the gcc-c++ installation status is as expected
OK: on host 100.168.83.7 the iproute installation status is as expected
OK: on host 100.168.83.7 the psmisc installation status is as expected
OK: on host 100.168.83.7 the fping installation status is as expected
OK: on host 100.168.83.7 the gcc-c++ installation status is as expected
OK: on host 100.168.83.6 the iproute installation status is as expected
OK: on host 100.168.83.6 the psmisc installation status is as expected
OK: on host 100.168.83.6 the fping installation status is as expected
OK: on host 100.168.83.6 the gcc-c++ installation status is as expected
OK: on host 100.168.83.5 the iproute installation status is as expected
OK: on host 100.168.83.5 the psmisc installation status is as expected
OK: on host 100.168.83.5 the fping installation status is as expected
OK: on host 100.168.83.5 the gcc-c++ installation status is as expected
OK: on host 100.168.83.10 the iproute installation status is as expected
OK: on host 100.168.83.10 the psmisc installation status is as expected
OK: on host 100.168.83.10 the fping installation status is as expected
OK: on host 100.168.83.10 the gcc-c++ installation status is as expected
OK: on host 100.168.83.11 the iproute installation status is as expected
OK: on host 100.168.83.11 the psmisc installation status is as expected
OK: on host 100.168.83.11 the fping installation status is as expected
OK: on host 100.168.83.11 the gcc-c++ installation status is as expected
OK: on host 100.168.83.4 the iproute installation status is as expected
OK: on host 100.168.83.4 the psmisc installation status is as expected
OK: on host 100.168.83.4 the fping installation status is as expected
OK: on host 100.168.83.4 the gcc-c++ installation status is as expected
OK: on host 100.168.83.9 TCP port 6668 seems to be free
OK: on host 100.168.83.8 TCP port 6668 seems to be free
OK: on host 100.168.83.3 TCP port 6668 seems to be free
OK: on host 100.168.83.2 TCP port 6668 seems to be free
OK: on host 100.168.83.1 TCP port 6668 seems to be free
OK: on host 100.168.83.7 TCP port 6668 seems to be free
OK: on host 100.168.83.6 TCP port 6668 seems to be free
OK: on host 100.168.83.5 TCP port 6668 seems to be free
OK: on host 100.168.83.10 TCP port 6668 seems to be free
OK: on host 100.168.83.11 TCP port 6668 seems to be free
OK: on host 100.168.83.4 TCP port 6668 seems to be free

Pre-flight RDMA checks:
OK: on host 100.168.83.9 the librdmacm installation status is as expected
OK: on host 100.168.83.9 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.9 the ibutils installation status is as expected
OK: on host 100.168.83.8 the librdmacm installation status is as expected
OK: on host 100.168.83.8 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.8 the ibutils installation status is as expected
OK: on host 100.168.83.3 the librdmacm installation status is as expected
OK: on host 100.168.83.3 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.3 the ibutils installation status is as expected
OK: on host 100.168.83.2 the librdmacm installation status is as expected
OK: on host 100.168.83.2 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.2 the ibutils installation status is as expected
OK: on host 100.168.83.1 the librdmacm installation status is as expected
OK: on host 100.168.83.1 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.1 the ibutils installation status is as expected
OK: on host 100.168.83.7 the librdmacm installation status is as expected
OK: on host 100.168.83.7 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.7 the ibutils installation status is as expected
OK: on host 100.168.83.6 the librdmacm installation status is as expected
OK: on host 100.168.83.6 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.6 the ibutils installation status is as expected
OK: on host 100.168.83.5 the librdmacm installation status is as expected
OK: on host 100.168.83.5 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.5 the ibutils installation status is as expected
OK: on host 100.168.83.10 the librdmacm installation status is as expected
OK: on host 100.168.83.10 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.10 the ibutils installation status is as expected
OK: on host 100.168.83.11 the librdmacm installation status is as expected
OK: on host 100.168.83.11 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.11 the ibutils installation status is as expected
OK: on host 100.168.83.4 the librdmacm installation status is as expected
OK: on host 100.168.83.4 the librdmacm-utils installation status is as expected
OK: on host 100.168.83.4 the ibutils installation status is as expected
OK: on host 100.168.83.9 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.9 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.8 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.8 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.3 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.3 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.2 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.2 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.1 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.1 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.7 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.7 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.6 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.6 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.5 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.5 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.10 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.10 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.11 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.11 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.4 the file /usr/bin/ibdev2netdev exists
OK: on host 100.168.83.4 the file /usr/sbin/ibstat exists
OK: on host 100.168.83.9 the RDMA port ib0 is on UP state
OK: on host 100.168.83.8 the RDMA port ib0 is on UP state
OK: on host 100.168.83.3 the RDMA port ib0 is on UP state
OK: on host 100.168.83.2 the RDMA port ib0 is on UP state
OK: on host 100.168.83.1 the RDMA port ib0 is on UP state
OK: on host 100.168.83.7 the RDMA port ib0 is on UP state
OK: on host 100.168.83.6 the RDMA port ib0 is on UP state
OK: on host 100.168.83.5 the RDMA port ib0 is on UP state
OK: on host 100.168.83.10 the RDMA port ib0 is on UP state
OK: on host 100.168.83.11 the RDMA port ib0 is on UP state
OK: on host 100.168.83.4 the RDMA port ib0 is on UP state
OK: on host 100.168.83.9 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.8 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.3 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.2 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.1 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.7 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.6 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.5 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.10 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.11 the RDMA port ib0 is CA mlx5_2/1
OK: on host 100.168.83.4 the RDMA port ib0 is CA mlx5_2/1
OK: all RDMA ports are up on all nodes

Creating log dir on hosts:
OK: on host 100.168.83.9 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.8 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.3 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.2 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.1 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.7 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.6 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.5 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.10 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.11 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created
OK: on host 100.168.83.4 logdir /root/ECE_NETWORK_READINESS-master/log/2019-09-23_23-09-07 has been created

Starting ping run from 100.168.83.9 to all nodes
Ping run from 100.168.83.9 to all nodes completed

Starting ping run from 100.168.83.8 to all nodes
Ping run from 100.168.83.8 to all nodes completed

Starting ping run from 100.168.83.3 to all nodes
Ping run from 100.168.83.3 to all nodes completed

Starting ping run from 100.168.83.2 to all nodes
Ping run from 100.168.83.2 to all nodes completed

Starting ping run from 100.168.83.1 to all nodes
Ping run from 100.168.83.1 to all nodes completed

Starting ping run from 100.168.83.7 to all nodes
Ping run from 100.168.83.7 to all nodes completed

Starting ping run from 100.168.83.6 to all nodes
Ping run from 100.168.83.6 to all nodes completed

Starting ping run from 100.168.83.5 to all nodes
Ping run from 100.168.83.5 to all nodes completed

Starting ping run from 100.168.83.10 to all nodes
Ping run from 100.168.83.10 to all nodes completed

Starting ping run from 100.168.83.11 to all nodes
Ping run from 100.168.83.11 to all nodes completed

Starting ping run from 100.168.83.4 to all nodes
Ping run from 100.168.83.4 to all nodes completed

Starting throughput tests. Please be patient.

Starting throughput run from 100.168.83.9 to all nodes
Completed throughput run from 100.168.83.9 to all nodes

Starting throughput run from 100.168.83.8 to all nodes
Completed throughput run from 100.168.83.8 to all nodes

Starting throughput run from 100.168.83.3 to all nodes
Completed throughput run from 100.168.83.3 to all nodes

Starting throughput run from 100.168.83.2 to all nodes
Completed throughput run from 100.168.83.2 to all nodes

Starting throughput run from 100.168.83.1 to all nodes
Completed throughput run from 100.168.83.1 to all nodes

Starting throughput run from 100.168.83.7 to all nodes
Completed throughput run from 100.168.83.7 to all nodes

Starting throughput run from 100.168.83.6 to all nodes
Completed throughput run from 100.168.83.6 to all nodes

Starting throughput run from 100.168.83.5 to all nodes
Completed throughput run from 100.168.83.5 to all nodes

Starting throughput run from 100.168.83.10 to all nodes
Completed throughput run from 100.168.83.10 to all nodes

Starting throughput run from 100.168.83.11 to all nodes
Completed throughput run from 100.168.83.11 to all nodes

Starting throughput run from 100.168.83.4 to all nodes
Completed throughput run from 100.168.83.4 to all nodes

Starting many to many nodes throughput test
Completed many to many nodes throughput test

Results for ICMP latency test 1:n
OK: on host 100.168.83.9 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.9 the 1:n maximum ICMP latency is 0.05 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.9 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.9 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.8 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.8 the 1:n maximum ICMP latency is 0.05 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.8 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.8 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.3 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.3 the 1:n maximum ICMP latency is 0.05 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.3 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.3 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.2 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.2 the 1:n maximum ICMP latency is 0.05 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.2 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.2 the 1:n standard deviation of ICMP latency is 0.0 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.1 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.1 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.1 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.1 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.7 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.7 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.7 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.7 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.6 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.6 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.6 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.6 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.5 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.5 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.5 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.5 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.10 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.10 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.10 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.10 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.11 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.11 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.11 the 1:n minimum ICMP latency is 0.03 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.11 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

OK: on host 100.168.83.4 the 1:n average ICMP latency is 0.04 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.4 the 1:n maximum ICMP latency is 0.06 msec. Which is lower than the KPI of 2.0 msec
OK: on host 100.168.83.4 the 1:n minimum ICMP latency is 0.02 msec. Which is lower than the KPI of 1.0 msec
OK: on host 100.168.83.4 the 1:n standard deviation of ICMP latency is 0.01 msec. Which is lower than the KPI of 0.33 msec

Results for throughput test
OK: on host 100.168.83.9 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.8 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host all at the same time the throughput test result is 59800 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.3 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.2 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.1 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.7 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.6 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.11 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.10 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.5 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: on host 100.168.83.4 the throughput test result is 12000 MB/sec. Which is higher than the KPI of 2000 MB/sec
OK: the difference of throughput between maximum and minimum values is 0.0%, which is less than 20% defined on the KPI

The following metrics are not part of the KPI and are shown for informational purposes only
INFO: The maximum throughput value is 12000.0
INFO: The minimum throughput value is 12000.0
INFO: The mean throughput value is 12000.0
INFO: The standard deviation throughput value is 0.0
INFO: The average NSD latency for 100.168.83.9 is 0.168331 msec
INFO: The average NSD latency for 100.168.83.8 is 0.168924 msec
INFO: The average NSD latency for all at the same time is 0.0381142 msec
INFO: The average NSD latency for 100.168.83.3 is 0.170929 msec
INFO: The average NSD latency for 100.168.83.2 is 0.168159 msec
INFO: The average NSD latency for 100.168.83.1 is 0.169102 msec
INFO: The average NSD latency for 100.168.83.7 is 0.169829 msec
INFO: The average NSD latency for 100.168.83.6 is 0.170446 msec
INFO: The average NSD latency for 100.168.83.11 is 0.17119 msec
INFO: The average NSD latency for 100.168.83.10 is 0.16971 msec
INFO: The average NSD latency for 100.168.83.5 is 0.16648 msec
INFO: The average NSD latency for 100.168.83.4 is 0.170825 msec
INFO: The standard deviation of NSD latency for 100.168.83.9 is 0.168331 msec
INFO: The standard deviation of NSD latency for 100.168.83.8 is 0.168924 msec
INFO: The standard deviation of NSD latency for all at the same time is 0.0381142 msec
INFO: The standard deviation of NSD latency for 100.168.83.3 is 0.170929 msec
INFO: The standard deviation of NSD latency for 100.168.83.2 is 0.168159 msec
INFO: The standard deviation of NSD latency for 100.168.83.1 is 0.169102 msec
INFO: The standard deviation of NSD latency for 100.168.83.7 is 0.169829 msec
INFO: The standard deviation of NSD latency for 100.168.83.6 is 0.170474 msec
INFO: The standard deviation of NSD latency for 100.168.83.11 is 0.17119 msec
INFO: The standard deviation of NSD latency for 100.168.83.10 is 0.16971 msec
INFO: The standard deviation of NSD latency for 100.168.83.5 is 0.16648 msec
INFO: The standard deviation of NSD latency for 100.168.83.4 is 0.170825 msec
INFO: The packet Rx error count for throughput test on 100.168.83.9 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.8 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.3 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.2 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.1 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.7 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.6 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.11 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.10 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.5 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on 100.168.83.4 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.9 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.8 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.3 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.2 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.1 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.7 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.6 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.11 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.10 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.5 is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on 100.168.83.4 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.9 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.8 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.3 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.2 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.1 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.7 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.6 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.11 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.10 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.5 is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test on 100.168.83.4 is equal to 0 packet[s]
INFO: The packet Rx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet Tx error count for throughput test on many to many is equal to 0 packet[s]
INFO: The packet retransmit count for throughput test many to many is equal to 0 packet[s]

The summary of this run:

	The 1:n ICMP average latency was successful in all nodes
	The 1:n throughput test was successful in all nodes

OK: All tests had been passed. You can proceed with the next steps
```
