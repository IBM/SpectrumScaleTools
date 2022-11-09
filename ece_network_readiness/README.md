This tool will run a network test across multiple nodes and compare the results against IBM Spectrum Scale Key Performance Indicators (KPI).
This tool attempts to hide much of the complexity of running network measurement tools, and present the results in an easy to interpret way.

**NOTE:** This test can require a long time to execute, depending on the number of nodes. This tool will display an estimated  runtime at startup.

**WARNING:** This is a network stress tool, hence it will stress the network. If you are using the network for some other service while running this tool you might feel service degradation. This tool, as stated on the license, it comes with no warranty of any kind.

**Running on RHEL 8.x Systems**
Because RHEL8 does not define python executable, either version 2 or version 3 needs to be defined as default python using the alternatives command:

*alternatives --config python*

You must pick either python2 or python3. This tool will work with either python version.  

An explanation of this can be found in many articles online, for example: https://developers.redhat.com/blog/2018/11/14/python-in-rhel-8/

**PREREQUISITES:** Before running this tool you **must** install the software prerequisites. Those are:

* gcc-c++, psmisc, and fping
* For Python3: python3-distro

The tool expects the SW to be installed as RPM package, and checks for those if you install those by other means you can still run this tool by using the ***--rpm_check_disabled*** flag. But only if you installed the prerequisites, the tool would crash if the SW is not installed and you disable the checks.

The gcc-c++ and psmisc RPM packages can be found on the [rhel-7-server-rpms](https://access.redhat.com/solutions/265523)  repository

The fping RPM package can be found on the [EPEL](https://fedoraproject.org/wiki/EPEL) repository, also on [RPMFIND](http://rpmfind.net/linux/rpm2html/search.php?query=fping)

Remarks:

  - The host where this tool is locally run must be part of the testbed of hosts being tested
  - As the runtime can be long if you plan to disconnect from the system run the tool with either *screen* or *tmux*. Do not use nohup as it would not spawn the subprocesses correclty
  - This tool runs on RedHat Enterprise Linux 7.5 or newer and 8.0 or newer on x86_64 and ppc64le mixed architectures.
  - Only Python standard libraries are used. But for Python3 we would need python3-distro
  - SSH root passwordless access must be configured from the node that runs the tool to all the nodes that participate in the tests. This tool will log an error if any node does not meet this requirement.
  - The minimum FPING_COUNT value for a valid ECE test must be 500, and a minimum of 10 (defaults to 500).
  - The minimum PERF_RUNTIME value for a valid ECE test must be 1200, and a minimum of 30 (defaults to 1200).
  - The number of hosts must be between 2 and 64. The upper limit is the tested limit. If you need to run it on more nodes contact us.
  - This tool generates a log directory with all the raw data output for future comparisons
  - This tool returns 0 if all tests are passed in all nodes, and returns an integer > 0 if any errors are detected.
  - TCP port 6668 needs to be reachable and not in use in all nodes.
  - Firewalld must be not running during the test.
  - This tool needs to be run on a local filesystem. No NFS, Spectrum Scale or alike.
  - For RDMA tests all Mellanox ports in the system, regardless they are part of the test or not, must be on Infiniband mode, not on Ethernet mode.
  - When using RDMA the IP addresses to be defined into the test should be the ones that would be part of the admin network on Spectrum Scale. When not using RDMA should be the ones to be on the daemon network.
  - When using RDMA ports that are tested must be up as shown by [*ibdev2netdev*](https://community.mellanox.com/s/article/ibdev2netdev)
  - When using RedHat Enterprise Linux 8 series you **must** select a default python version with the command: *alternatives --config python*
  - When you set a bond device on top of RDMA devices, be sure that ''ibdev2netdev'' reports only ib names not bond names. If it shows bond devices port, those will find as down by this tool


To run the test without a JSON file already populated with the Spectrum Scale daemon IP (if RDMA use the admin ones) addresses and generating one JSON for future runs:

```shell
# ./koet.py --hosts 10.10.12.92,10.10.12.93,10.10.12.94,10.10.12.95 --save-hosts
```

So to run the test with a JSON file already populated with the admin IP addresses: (look at the example already populated one)

```shell
# ./koet.py
```

To run a RDMA (testing the availability of ib0 and ib1 on all nodes) test with a JSON already populated:
```shell
# ./koet.py --rdma ib0,ib1
```

KNOWN ISSUES:
  - There are no known issues at this time. If you encounter problems please contact open an issue in our repository (https://github.ibm.com/SpectrumScaleTools/ECE_NETWORK_READINESS/issues)

TODO:
  - Add precompiled versions of throughput tool so no compiling is needed
  - Add an option to load previous test results and compare

Usage help:
```
# ./koet.py -h
usage: koet.py [-h] [-l KPI_LATENCY] [-c FPING_COUNT] [--hosts HOSTS_CSV]
               [-m KPI_THROUGHPUT] [-p PERF_RUNTIME] [--rdma PORTS_CSV]
               [--rpm_check_disabled] [--save-hosts] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -l KPI_LATENCY, --latency KPI_LATENCY
                        The KPI latency value as float. The maximum required
                        value for certification is 1.0 msec
  -c FPING_COUNT, --fping_count FPING_COUNT
                        The number of fping counts to run per node and test.
                        The value has to be at least 2 seconds.The minimum
                        required value for certification is 500
  --hosts HOSTS_CSV     IP addresses of hosts on CSV format. Using this
                        overrides the hosts.json file.
  -m KPI_THROUGHPUT, --min_throughput KPI_THROUGHPUT
                        The minimum MB/sec required to pass the test. The
                        minimum required value for certification is 2000
  -p PERF_RUNTIME, --perf_runtime PERF_RUNTIME
                        The seconds of nsdperf runtime per test. The value has
                        to be at least 10 seconds. The minimum required value
                        for certification is 1200
  --rdma PORTS_CSV      Enables RDMA and ports to be check on CSV format
                        (ib0,ib1,...). Must be using OS device names, not mlx
                        names.
  --rpm_check_disabled  Disables the RPM prerequisites check. Use only if you
                        are sure all required software is installed and no RPM
                        were used to install the required prerequisites
  --save-hosts          [over]writes hosts.json with the hosts passed with
                        --hosts. It does not prompt for confirmation when
                        overwriting
  -v, --version         show program version number and exit
```

An output example:
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

At this point you can see the estimated runtime, consider using screen or alike. If you modify the number of fpings or the latency KPI you might see warning messages as below:

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

The following is the output of a successful run. Please notice that the output is color coded.

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

And RDMA successful run:

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
