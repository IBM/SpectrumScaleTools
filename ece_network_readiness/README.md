This tool uses fping and nsdperf to run test agianst multiple hosts and presents the results in a way that is easy to interpret. compares the test results with Key Performance Indicators (KPI) and determines if the network was ready to run IBM Storage Scale Erasure Code Edition.

**NOTE:**
  Test instance launched by this tool may take a long time. The tool will display an estimated time consumption at startup.
  It is recommended to run instance under session of screen or tmux.

**WARNING:**
  Do not use this tool against any production environment because running this tool would seriously affect network traffic.
  This tool comes with no warranty of any kind.

**Prerequisite:**
  Passwordless ssh. All hosts participated in the test must ssh each other as root without password.
  Firewalld must be inactive while this tool is running.
  Socket port 6668 must be idle if test network with TCP/IP protocol.

**Dependent Software:**
  Dependent package is described in packages.json file.
  If you do install the packages, run the tool with option: ***--no-package-check***.
  The tool would quit if dependent package was not installed although you disabled the check.
  The fping package can be found from [GITHUB](https://github.com/schweikert/fping), [EPEL](https://fedoraproject.org/wiki/EPEL), [RPMFIND](http://rpmfind.net/linux/rpm2html/search.php?query=fping) or somewhere else.


Remarks:

  - The launcher host of this tool must be a member of the cluster.
  - The number of hosts must be between 2 and 64. Contact IBM if need to run against more hosts.
  - If test with TCP/IP protocol, the IP addresses followed '--hosts' option or in hosts.json should be from GPFS daemon network.
  - If test with RDMA protocol, the IP addresses followed '--hosts' option or in hosts.json can be from cluster admin network.
  - If test with RDMA protocol, Mellanox ports must be in Infiniband mode and have the same CA(Channel Adapter) name.
  - If RDMA devices have been set as bond mode, make sure that [*ibdev2netdev*](https://community.mellanox.com/s/article/ibdev2netdev) shows IB device name rather than bond name.

Usage:
```
usage: koet.py [-h] [--hosts CSV_IPV4] [-s] [-c COUNT] [-t TIME] [-r THREAD]
               [-p PARALLEL] [-b BUFFSIZE] [-o SOCKSIZE] [--rdma PORTS_CSV]
               [--no-package-check] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --hosts CSV_IPV4      IPv4 addresses in CSV format. E.g., IP0,IP1,...
  -s, --save-hosts      [Over]write hosts.json with IP addresses followed
                        --hosts
  -c COUNT, --fping-count COUNT
                        count of fping packets to send to each target. The
                        minimum value can be set to 2 packets for quick test.
                        For certification, it is at least 500 packets
  -t TIME, --test-time TIME
                        test time per nsdperf instance in sec. The minimum
                        value can be set to 10 sec for quick test. For
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
                        buffer size for each I/O of nsdperf in byte The
                        minimum value is 4096 bytes and the maximum value is
                        16777216 bytes. For certification, it is 2097152 bytes
  -o SOCKSIZE, --socket-size SOCKSIZE
                        maximum socket send and receive buffer size in byte. 0
                        means the system default setting. The maximum value is
                        104857600 bytes. This tool implicitly sets the socket
                        size to the I/O buffer size if socket size was not
                        specified
  --rdma PORTS_CSV      assign ports in CSV format. E.g., ib0,ib1,... Use
                        logical device name rather than mlx name
  --no-package-check    disable dependent package check
  -v, --version         show program's version number and exit
```

Launch the test with TCP/IP protocol. Use GPFS daemon IP addresses then save them to hosts.json for future runs.
```
# python3 koet.py --hosts 10.168.2.101,10.168.2.105,10.168.2.109,10.168.2.113 -s
```

Launch the test with hosts.json that already populated, with TCP/IP protocol.
```
# python3 koet.py
```

Launch the test with hosts.json that already populated, with RDMA protocol.
```
# python3 koet.py --rdma ib0,ib1
```

A successful example with TCP/IP protocol.
```
# python3 koet.py

Welcome to Network Readiness 1.30

The purpose of this tool is to obtain network metrics of a list of hosts then compare them with certain KPIs
Please access to https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

IMPORTANT WARNING:
  Do NOT run this tool in production environment because it would generate heavy network traffic.
NOTE:
  The latency and throughput numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] The fping count per instance needs at least 500 request packets. Current setting is 500 packets
[ INFO  ] The nsdperf needs at least 1200 sec test time per instance. Current setting is 1200 sec
[ INFO  ] The nsdperf needs 32 test thread per instance. Current setting is 32
[ INFO  ] The nsdperf needs 2097152 bytes buffer size. Current setting is 2097152 bytes

[ INFO  ] The total time consumption of running this network readiness instance is estimated to take at least 135 minutes

Type 'y' to continue, 'n' to stop
Continue? <y/n>: y

[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.101
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.101 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.105
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.105 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.109
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.109 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.113
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.113 with strict host key checking

[ INFO  ] Check if required package is available according to packages.json with version 2.0
[ INFO  ] 10.168.2.101 has fping installed
[ INFO  ] 10.168.2.101 has psmisc installed
[ INFO  ] 10.168.2.101 has iproute installed
[ INFO  ] 10.168.2.101 has gcc-c++ installed

[ INFO  ] 10.168.2.105 has fping installed
[ INFO  ] 10.168.2.105 has psmisc installed
[ INFO  ] 10.168.2.105 has iproute installed
[ INFO  ] 10.168.2.105 has gcc-c++ installed

[ INFO  ] 10.168.2.109 has fping installed
[ INFO  ] 10.168.2.109 has psmisc installed
[ INFO  ] 10.168.2.109 has iproute installed
[ INFO  ] 10.168.2.109 has gcc-c++ installed

[ INFO  ] 10.168.2.113 has fping installed
[ INFO  ] 10.168.2.113 has psmisc installed
[ INFO  ] 10.168.2.113 has iproute installed
[ INFO  ] 10.168.2.113 has gcc-c++ installed

[ INFO  ] 10.168.2.101 has inactive firewalld service
[ INFO  ] 10.168.2.105 has inactive firewalld service
[ INFO  ] 10.168.2.109 has inactive firewalld service
[ INFO  ] 10.168.2.113 has inactive firewalld service

[ INFO  ] Port 6668 on host 10.168.2.101 is free
[ INFO  ] Port 6668 on host 10.168.2.105 is free
[ INFO  ] Port 6668 on host 10.168.2.109 is free
[ INFO  ] Port 6668 on host 10.168.2.113 is free

[ INFO  ] Starts 1 to n fping instances
[ INFO  ] 10.168.2.101 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.101 completed fping test
[ INFO  ] 10.168.2.105 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.105 completed fping test
[ INFO  ] 10.168.2.109 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.109 completed fping test
[ INFO  ] 10.168.2.113 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.113 completed fping test

[ INFO  ] Starts one to many nsdperf instances
[ INFO  ] 10.168.2.101 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.101 to other hosts completed
[ INFO  ] 10.168.2.105 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.105 to other hosts completed
[ INFO  ] 10.168.2.109 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.109 to other hosts completed
[ INFO  ] 10.168.2.113 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.113 to other hosts completed

[ INFO  ] Starts many to many nsdperf instance
[ INFO  ] It will take at least 1200 sec
[ INFO  ] Many to many nsdperf instance completed

[ INFO  ] ICMP latency results of fping 1:n test
[ INFO  ] 10.168.2.101 has 0.17 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.105 has 0.15 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.109 has 0.16 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.113 has 0.15 msec ICMP average latency which meets the required average latency KPI 1.0 msec

[ INFO  ] 10.168.2.101 has 0.29 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.105 has 0.23 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.109 has 0.23 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.113 has 0.25 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec

[ INFO  ] 10.168.2.101 has 0.02 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.105 has 0.04 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.109 has 0.04 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.113 has 0.02 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec

[ INFO  ] 10.168.2.101 has 0.01 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.105 has 0.01 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.109 has 0.01 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.113 has 0.02 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec

[ INFO  ] Throughput results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 9270 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.105 has 9230 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.109 has 9330 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.113 has 9000 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] The average network throughput is 9207.5 MB/sec
[ INFO  ] The maximum network throughput is 9330.0 MB/sec
[ INFO  ] The minimum network throughput is 9000.0 MB/sec
[ INFO  ] The standard deviation of network throughput is 144.31 MB/sec
[ INFO  ] Define difference percentage as 100 * (max - min) / max
[ INFO  ] All hosts have 3.54% network throughput difference which meets the required 20.0% difference KPI

[ INFO  ] Latency results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 1.48777 msec average NSD latency
[ INFO  ] 10.168.2.105 has 1.49229 msec average NSD latency
[ INFO  ] 10.168.2.109 has 1.48 msec average NSD latency
[ INFO  ] 10.168.2.113 has 1.53072 msec average NSD latency
[ INFO  ] 10.168.2.101 has 0.520861 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.105 has 0.523878 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.109 has 0.511029 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.113 has 0.5476 msec standard deviation of NSD latency

[ INFO  ] Packet results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.105 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.109 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.113 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.101 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.105 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.109 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.113 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.101 has retransmit 0 NSD packet
[ INFO  ] 10.168.2.105 has retransmit 0 NSD packet
[ INFO  ] 10.168.2.109 has retransmit 1 NSD packet
[ INFO  ] 10.168.2.113 has retransmit 0 NSD packet

[ INFO  ] Throughput results of nsdperf m:m test
[ INFO  ] Many to many network throughput is 13500.0 MB/sec

[ INFO  ] Latency results of nsdperf m:m test
[ INFO  ] Many to many average NSD latency is 1.40864 msec
[ INFO  ] Many to many standard deviation of NSD latency is 0.487289 msec

[ INFO  ] Packet results of nsdperf m:m test
[ INFO  ] Many to many NSD Rx total error is 0 packet
[ INFO  ] Many to many NSD Rx total error is 0 packet
[ INFO  ] Many to many NSD total retransmit is 2 packet

[ INFO  ] Summary of NSD throughput can be found in /u/czbj/bugfix_ece_network_readiness/log/2023-10-11_21-36-40/nsd_throughput.csv

[ INFO  ] Summary of this instance
[ INFO  ] All fping tests are passed
[ INFO  ] All nsdperf tests are passed

[ INFO  ] All network tests have passed. You can proceed to the next step
```

A successful example with RDMA protocol.
```
# python3 koet.py --rdma ib0,ib1

Welcome to Network Readiness 1.30

The purpose of this tool is to obtain network metrics of a list of hosts then compare them with certain KPIs
Please access to https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

IMPORTANT WARNING:
  Do NOT run this tool in production environment because it would generate heavy network traffic.
NOTE:
  The latency and throughput numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] The fping count per instance needs at least 500 request packets. Current setting is 500 packets
[ INFO  ] The nsdperf needs at least 1200 sec test time per instance. Current setting is 1200 sec
[ INFO  ] The nsdperf needs 32 test thread per instance. Current setting is 32
[ INFO  ] The nsdperf needs 2097152 bytes buffer size. Current setting is 2097152 bytes

[ INFO  ] The total time consumption of running this network readiness instance is estimated to take at least 135 minutes

Type 'y' to continue, 'n' to stop
Continue? <y/n>: y

[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.101
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.101 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.105
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.105 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.109
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.109 with strict host key checking
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.113
[ INFO  ] localhost succeeded to passwordless ssh 10.168.2.113 with strict host key checking

[ INFO  ] Check if required package is available according to packages.json with version 2.0
[ INFO  ] 10.168.2.101 has fping installed
[ INFO  ] 10.168.2.101 has psmisc installed
[ INFO  ] 10.168.2.101 has iproute installed
[ INFO  ] 10.168.2.101 has gcc-c++ installed
[ INFO  ] 10.168.2.101 has librdmacm installed
[ INFO  ] 10.168.2.101 has librdmacm-utils installed
[ INFO  ] 10.168.2.101 has rdma-core-devel installed
[ INFO  ] 10.168.2.101 has ibutils2 installed

[ INFO  ] 10.168.2.105 has fping installed
[ INFO  ] 10.168.2.105 has psmisc installed
[ INFO  ] 10.168.2.105 has iproute installed
[ INFO  ] 10.168.2.105 has gcc-c++ installed
[ INFO  ] 10.168.2.105 has librdmacm installed
[ INFO  ] 10.168.2.105 has librdmacm-utils installed
[ INFO  ] 10.168.2.105 has rdma-core-devel installed
[ INFO  ] 10.168.2.105 has ibutils2 installed

[ INFO  ] 10.168.2.109 has fping installed
[ INFO  ] 10.168.2.109 has psmisc installed
[ INFO  ] 10.168.2.109 has iproute installed
[ INFO  ] 10.168.2.109 has gcc-c++ installed
[ INFO  ] 10.168.2.109 has librdmacm installed
[ INFO  ] 10.168.2.109 has librdmacm-utils installed
[ INFO  ] 10.168.2.109 has rdma-core-devel installed
[ INFO  ] 10.168.2.109 has ibutils2 installed

[ INFO  ] 10.168.2.113 has fping installed
[ INFO  ] 10.168.2.113 has psmisc installed
[ INFO  ] 10.168.2.113 has iproute installed
[ INFO  ] 10.168.2.113 has gcc-c++ installed
[ INFO  ] 10.168.2.113 has librdmacm installed
[ INFO  ] 10.168.2.113 has librdmacm-utils installed
[ INFO  ] 10.168.2.113 has rdma-core-devel installed
[ INFO  ] 10.168.2.113 has ibutils2 installed

[ INFO  ] 10.168.2.101 has inactive firewalld service
[ INFO  ] 10.168.2.105 has inactive firewalld service
[ INFO  ] 10.168.2.109 has inactive firewalld service
[ INFO  ] 10.168.2.113 has inactive firewalld service

[ INFO  ] Port 6668 on host 10.168.2.101 is free
[ INFO  ] Port 6668 on host 10.168.2.105 is free
[ INFO  ] Port 6668 on host 10.168.2.109 is free
[ INFO  ] Port 6668 on host 10.168.2.113 is free

[ INFO  ] 10.168.2.101 has 'ib0' with 'Up' state
[ INFO  ] 10.168.2.101 has 'ib1' with 'Up' state
[ INFO  ] 10.168.2.101 has 'ib0' with CA(Channel Adapter) name 'mlx5_0/1'
[ INFO  ] 10.168.2.101 has 'ib1' with CA(Channel Adapter) name 'mlx5_1/1'

[ INFO  ] 10.168.2.105 has 'ib0' with 'Up' state
[ INFO  ] 10.168.2.105 has 'ib1' with 'Up' state
[ INFO  ] 10.168.2.105 has 'ib0' with CA(Channel Adapter) name 'mlx5_0/1'
[ INFO  ] 10.168.2.105 has 'ib1' with CA(Channel Adapter) name 'mlx5_1/1'

[ INFO  ] 10.168.2.109 has 'ib0' with 'Up' state
[ INFO  ] 10.168.2.109 has 'ib1' with 'Up' state
[ INFO  ] 10.168.2.109 has 'ib0' with CA(Channel Adapter) name 'mlx5_0/1'
[ INFO  ] 10.168.2.109 has 'ib1' with CA(Channel Adapter) name 'mlx5_1/1'

[ INFO  ] 10.168.2.113 has 'ib0' with 'Up' state
[ INFO  ] 10.168.2.113 has 'ib1' with 'Up' state
[ INFO  ] 10.168.2.113 has 'ib0' with CA(Channel Adapter) name 'mlx5_0/1'
[ INFO  ] 10.168.2.113 has 'ib1' with CA(Channel Adapter) name 'mlx5_1/1'

[ INFO  ] 10.168.2.101 has 'mlx5_0' with InfiniBand Link Layer
[ INFO  ] 10.168.2.101 has 'mlx5_1' with InfiniBand Link Layer

[ INFO  ] 10.168.2.105 has 'mlx5_0' with InfiniBand Link Layer
[ INFO  ] 10.168.2.105 has 'mlx5_1' with InfiniBand Link Layer

[ INFO  ] 10.168.2.109 has 'mlx5_0' with InfiniBand Link Layer
[ INFO  ] 10.168.2.109 has 'mlx5_1' with InfiniBand Link Layer

[ INFO  ] 10.168.2.113 has 'mlx5_0' with InfiniBand Link Layer
[ INFO  ] 10.168.2.113 has 'mlx5_1' with InfiniBand Link Layer

[ INFO  ] Starts 1 to n fping instances
[ INFO  ] 10.168.2.101 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.101 completed fping test
[ INFO  ] 10.168.2.105 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.105 completed fping test
[ INFO  ] 10.168.2.109 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.109 completed fping test
[ INFO  ] 10.168.2.113 starts fping instance to all hosts
[ INFO  ] It will take at least 500 sec
[ INFO  ] 10.168.2.113 completed fping test

[ INFO  ] Starts one to many nsdperf instances
[ INFO  ] 10.168.2.101 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.101 to other hosts completed
[ INFO  ] 10.168.2.105 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.105 to other hosts completed
[ INFO  ] 10.168.2.109 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.109 to other hosts completed
[ INFO  ] 10.168.2.113 starts nsdperf instance to all nodes
[ INFO  ] It will take at least 1200 sec
[ INFO  ] nsdperf instance from 10.168.2.113 to other hosts completed

[ INFO  ] Starts many to many nsdperf instance
[ INFO  ] It will take at least 1200 sec
[ INFO  ] Many to many nsdperf instance completed

[ INFO  ] ICMP latency results of fping 1:n test
[ INFO  ] 10.168.2.101 has 0.14 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.105 has 0.14 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.109 has 0.15 msec ICMP average latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.113 has 0.16 msec ICMP average latency which meets the required average latency KPI 1.0 msec

[ INFO  ] 10.168.2.101 has 0.25 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.105 has 0.23 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.109 has 0.24 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec
[ INFO  ] 10.168.2.113 has 0.25 msec ICMP maximum latency which meets the required maximum latency KPI 2.0 msec

[ INFO  ] 10.168.2.101 has 0.02 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.105 has 0.02 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.109 has 0.03 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec
[ INFO  ] 10.168.2.113 has 0.04 msec ICMP minimum latency which meets the required average latency KPI 1.0 msec

[ INFO  ] 10.168.2.101 has 0.02 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.105 has 0.03 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.109 has 0.01 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec
[ INFO  ] 10.168.2.113 has 0.02 msec ICMP latency standard deviation which meets the required latency standard deviation KPI 0.33 msec

[ INFO  ] Throughput results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 24000 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.105 has 24000 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.109 has 24600 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] 10.168.2.113 has 24600 MB/sec network throughput which meets the required 2000 MB/sec throughput KPI
[ INFO  ] The average network throughput is 24300.0 MB/sec
[ INFO  ] The maximum network throughput is 24600.0 MB/sec
[ INFO  ] The minimum network throughput is 24000.0 MB/sec
[ INFO  ] The standard deviation of network throughput is 346.41 MB/sec
[ INFO  ] Define difference percentage as 100 * (max - min) / max
[ INFO  ] All hosts have 2.44% network throughput difference which meets the required 20.0% difference KPI

[ INFO  ] Latency results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 2.70495 msec average NSD latency
[ INFO  ] 10.168.2.105 has 2.7182 msec average NSD latency
[ INFO  ] 10.168.2.109 has 2.62801 msec average NSD latency
[ INFO  ] 10.168.2.113 has 2.61933 msec average NSD latency
[ INFO  ] 10.168.2.101 has 0.543721 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.105 has 0.549416 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.109 has 0.528477 msec standard deviation of NSD latency
[ INFO  ] 10.168.2.113 has 0.526968 msec standard deviation of NSD latency

[ INFO  ] Packet results of nsdperf 1:m test
[ INFO  ] 10.168.2.101 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.105 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.109 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.113 has 0 packet NSD Rx error
[ INFO  ] 10.168.2.101 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.105 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.109 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.113 has 0 packet NSD Tx error
[ INFO  ] 10.168.2.101 has retransmit 0 NSD packet
[ INFO  ] 10.168.2.105 has retransmit 0 NSD packet
[ INFO  ] 10.168.2.109 has retransmit 1 NSD packet
[ INFO  ] 10.168.2.113 has retransmit 0 NSD packet

[ INFO  ] Throughput results of nsdperf m:m test
[ INFO  ] Many to many network throughput is 47900.0 MB/sec

[ INFO  ] Latency results of nsdperf m:m test
[ INFO  ] Many to many average NSD latency is 2.33601 msec
[ INFO  ] Many to many standard deviation of NSD latency is 0.563942 msec

[ INFO  ] Packet results of nsdperf m:m test
[ INFO  ] Many to many NSD Rx total error is 0 packet
[ INFO  ] Many to many NSD Rx total error is 0 packet
[ INFO  ] Many to many NSD total retransmit is 0 packet

[ INFO  ] Summary of NSD throughput can be found in /u/czbj/bugfix_ece_network_readiness/log/2023-10-12_05-26-34/nsd_throughput.csv

[ INFO  ] Summary of this instance
[ INFO  ] All fping tests are passed
[ INFO  ] All nsdperf tests are passed

[ INFO  ] All network tests have passed. You can proceed to the next step
```
