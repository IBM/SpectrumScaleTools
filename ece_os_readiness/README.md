This tool assesses the readiness of a single node to install IBM Spectrum Scale Erasure Code Edition (ECE). This tool only checks for requirement of a system that can run ECE, no other software or middleware on top in the same server.

Run this tool before installing ECE with the Spectrum Scale toolkit, it is used by the toolkit to do a more comprehensive node checking from a cluster perspective, this tool checks at node level. Each run generates a JSON file with name IP_ADDRESS.json where data is saved. In standalone mode this file is only for reference.

**IMPORTANT**
This tool does not overrule the official documentation of the product. The requirements stated on the official documentation as "Minimum hardware requirements and precheck" in https://www.ibm.com/docs/en/spectrum-scale-ece

**Known limitations**
- Current code works correctly only if the system had one or none SAS card. It does not work properly with more than one SAS card yet. Results cannot be trusted when more than one SAS card is on the system. Multiple SAS cards checking is planned to be addressed in future.
- On RHEL 8 series there is a warning message at the end of the run, that is because the current version of dmidecode and python modules that are shipped with RHEL from OS upstream. When the version catch up on the OS upstream repositories that message would go away. The below warning can be ignored for now.
```
# SMBIOS implementations newer than version 2.7 are not
# fully supported by this version of dmidecode.
```
- This tool can run on RHEL 8 systems only with python3. This is due to dependencies that are not available on RHEL 8 series and python2.

**PREREQUISITES:** Before running this tool you **must** install the software prerequisites. Those are:
 * RPM packages that are listed on on packages.json file with a value of 0.
 * For Python2 -> python-dmidecode and python-ethtool RPM packages.
 * For Python3 -> python3-dmidecode and python3-ethtool python3-distro RPM packages and python pyyaml module, please check [pyyaml documentation](https://pyyaml.org/wiki/PyYAMLDocumentation) 
 * nvme-cli RPM package if NVME drive[s] exists in the system
 * storcli if SAS card[s] exists in the system, ad storcli must be able ot manage those SAS cards
 * megacli is not supported by ECE nor this tool as stated on the above linked "Minimum hardware requirements and precheck"

Parameter (--ip) is required, pass the local IP where RAID traffic is going to happen. It must be an IPv4 address rather than a hostname.

```
# ./mor.py -h
usage: mor.py [-h] [--FIPS] --ip IPv4_ADDRESS [--path PATH/] [--no-cpu-check]
              [--no-md5-check] [--no-mem-check] [--no-os-check]
              [--no-packages-check] [--no-net-check] [--no-storage-check]
              [--no-sysctl-check] [--no-tuned-check] [--toolkit] [-v]

optional arguments:
  -h, --help           show this help message and exit
  --FIPS               Does not run parts of the code that cannot run on FIPS
                       systems. The run with this parameter is not valid for
                       acceptance.
  --ip IPv4_ADDRESS    Local IP address linked to device used for NSD
  --path PATH/         Path where JSON files are located. Defaults to local
                       directory
  --no-cpu-check       Does not run CPU checks
  --no-md5-check       Does not check MD5 of JSON files
  --no-mem-check       Does not run memory checks
  --no-os-check        Does not run OS checks
  --no-packages-check  Does not run packages checks
  --no-net-check       Does not run network checks
  --no-storage-check   Does not run storage checks
  --no-sysctl-check    Does not run sysctl checks
  --no-tuned-check     Does not run tuned checks
  --toolkit            To indicate is being run from Spectrum Scale install
                       toolkit
  -v, --version        show program's version number and exit
```

  Use --no-*-check parameters to skip certain item checking. In order to install ECE, all the tests must pass on all nodes. You can additionally gather the JSON output files and run ece_os_overview.

  A "good enough" run is shown below:

  ```
# ./mor.py --ip 10.168.2.17
[ INFO  ] c72f4m5u17-ib0 IBM Spectrum Scale Erasure Code Edition OS readiness version 1.11
[ INFO  ] c72f4m5u17-ib0 This tool comes with absolute not warranty
[ INFO  ] c72f4m5u17-ib0 Please check https://github.com/IBM/SpectrumScaleTools for details
[ INFO  ] c72f4m5u17-ib0 JSON files versions:
[ INFO  ] c72f4m5u17-ib0 	supported OS:		1.0
[ INFO  ] c72f4m5u17-ib0 	sysctl: 		0.7
[ INFO  ] c72f4m5u17-ib0 	packages: 		1.2
[ INFO  ] c72f4m5u17-ib0 	SAS adapters:		1.2
[ INFO  ] c72f4m5u17-ib0 	NIC adapters:		1.0
[ INFO  ] c72f4m5u17-ib0 	HW requirements:	1.1
[ INFO  ] c72f4m5u17-ib0 checking processor compatibility
[ INFO  ] c72f4m5u17-ib0 x86_64 processor is supported to run ECE
[ INFO  ] c72f4m5u17-ib0 checking socket count
[ INFO  ] c72f4m5u17-ib0 is Intel based
[ INFO  ] c72f4m5u17-ib0 has 2 sockets which complies with the requirements to support ECE 
[ INFO  ] c72f4m5u17-ib0 checking core count
[ INFO  ] c72f4m5u17-ib0 socket 0x0048 has 10 core[s]
[ INFO  ] c72f4m5u17-ib0 socket 0x0044 has 10 core[s]
[ INFO  ] c72f4m5u17-ib0 has a total of 20 cores which complies with the requirements to support ECE
[ INFO  ] c72f4m5u17-ib0 Red Hat Enterprise Linux Server 7.5 is a supported OS to run ECE
[ INFO  ] c72f4m5u17-ib0 checking packages install status
[ INFO  ] c72f4m5u17-ib0 installation status of numactl-libs is as expected
[ INFO  ] c72f4m5u17-ib0 installation status of numactl is as expected
[ INFO  ] c72f4m5u17-ib0 installation status of sg3_utils is as expected
[ INFO  ] c72f4m5u17-ib0 installation status of tuned is as expected
[ INFO  ] c72f4m5u17-ib0 installation status of dmidecode is as expected
[ INFO  ] c72f4m5u17-ib0 installation status of pciutils is as expected
[ INFO  ] c72f4m5u17-ib0 checking memory
[ INFO  ] c72f4m5u17-ib0 total memory is 125 GB, which is sufficient to run ECE
[ WARN  ] c72f4m5u17-ib0 not all 24 DIMM slot[s] are populated. This system has 20 empty DIMM slot[s]. This is not recommended to run ECE
[ INFO  ] c72f4m5u17-ib0 all populated DIMM slots have same memory size of 32767 MB
[ INFO  ] c72f4m5u17-ib0 checking SAS adapters
[ INFO  ] c72f4m5u17-ib0 has SAS3516 adapter which is supported by ECE. The disks under this SAS adapter could be used by ECE
[ INFO  ] c72f4m5u17-ib0 checking that needed software for SAS is installed
[ INFO  ] c72f4m5u17-ib0 checking packages install status
[ INFO  ] c72f4m5u17-ib0 installation status of storcli is as expected
[ INFO  ] c72f4m5u17-ib0 has 3 HDD drive[s] on the SAS adapter the same size that ECE can use
[ INFO  ] c72f4m5u17-ib0 all SAS drives have Volatile Write Cache disabled
[ WARN  ] c72f4m5u17-ib0 has 4 SATA SSD drive[s] on the SAS adapter. SATA drives are not supported by ECE. Do not use them for ECE
[ WARN  ] c72f4m5u17-ib0 no SSD disk[s] usable by ECE found. The drives under SAS controller must be on JBOD mode and be SAS drives
[ INFO  ] c72f4m5u17-ib0 checking NVMe devices
[ INFO  ] c72f4m5u17-ib0 has 2 NVMe device[s] detected
[ INFO  ] c72f4m5u17-ib0 checking that needed software for NVMe is installed
[ INFO  ] c72f4m5u17-ib0 checking packages install status
[ INFO  ] c72f4m5u17-ib0 installation status of nvme-cli is as expected
[ INFO  ] c72f4m5u17-ib0 all NVMe devices have the same size
[ INFO  ] c72f4m5u17-ib0 all NVMe devices have Volatile Write Cache disabled
[ INFO  ] c72f4m5u17-ib0 has at least one SSD or NVMe device that ECE can use. This is required to run ECE
[ INFO  ] c72f4m5u17-ib0 has 5 drives that ECE can use
[ INFO  ] c72f4m5u17-ib0 checking NIC adapters
[ INFO  ] c72f4m5u17-ib0 has ConnectX-4 adapter which is supported by ECE
[ INFO  ] c72f4m5u17-ib0 checking 10.168.2.17 device and link speed
[ INFO  ] c72f4m5u17-ib0 the IP address 10.168.2.17 is found on device ib0
[ INFO  ] c72f4m5u17-ib0 interface ib0 has a link of 100000 Mb/s. Which is supported to run ECE
[ INFO  ] c72f4m5u17-ib0 current active profile is throughput-performance
[ INFO  ] c72f4m5u17-ib0 tuned profile is fully matching the active profile
[ INFO  ] c72f4m5u17-ib0 checking sysctl settings
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_sack it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 net.core.rmem_default it is set to the recommended value of 16777216
[ INFO  ] c72f4m5u17-ib0 net.core.netdev_budget it is set to the recommended value of 600
[ INFO  ] c72f4m5u17-ib0 net.core.wmem_default it is set to the recommended value of 16777216
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_slow_start_after_idle it is set to the recommended value of 0
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_adv_win_scale it is set to the recommended value of 2
[ INFO  ] c72f4m5u17-ib0 net.core.rmem_max it is set to the recommended value of 16777216
[ INFO  ] c72f4m5u17-ib0 net.core.somaxconn it is set to the recommended value of 10000
[ INFO  ] c72f4m5u17-ib0 vm.min_free_kbytes it is set to the recommended value of 512000
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_tw_reuse it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_tw_recycle it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 kernel.shmmax it is set to the recommended value of 13743895347
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_low_latency it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_window_scaling it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 net.core.optmem_max it is set to the recommended value of 16777216
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_max_syn_backlog it is set to the recommended value of 8192
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_timestamps it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_rmem it is set to the recommended value of 4096 4224000 16777216
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_wmem it is set to the recommended value of 4096 4224000 16777216
[ INFO  ] c72f4m5u17-ib0 net.core.wmem_max it is set to the recommended value of 16777216
[ INFO  ] c72f4m5u17-ib0 net.ipv4.tcp_syn_retries it is set to the recommended value of 8
[ INFO  ] c72f4m5u17-ib0 net.core.netdev_max_backlog it is set to the recommended value of 300000
[ INFO  ] c72f4m5u17-ib0 kernel.sysrq it is set to the recommended value of 1
[ INFO  ] c72f4m5u17-ib0 kernel.numa_balancing it is set to the recommended value of 0

	Summary of this standalone run:
		Run started at 2019-11-28 03:59:23.876296
		ECE Readiness version 1.11
		Hostname: c72f4m5u17-ib0
		OS: Red Hat Enterprise Linux Server 7.5
		Architecture: x86_64
		Sockets: 2
		Cores per socket: [10, 10]
		Memory: 125 GBytes
		DIMM slots: 24
		DIMM slots in use: 4
		SAS HBAs in use: SAS3516
		JBOD SAS HDD drives: 3
		JBOD SAS SSD drives: 0
		NVMe drives: 2
		HCAs in use: ConnectX-4
		Link speed: 100000
		Run ended at 2019-11-28 03:59:26.514697

		./10.168.2.17.json contains information about this run

[ INFO ] c72f4m5u17-ib0 system can run IBM Spectrum Scale Erasure Code Edition
  ```

  A failed run is shown below:

  ```
# ./mor.py --ip 10.10.12.92
[ INFO  ] mestor01 IBM Spectrum Scale Erasure Code Edition OS readiness version 1.11
[ INFO  ] mestor01 This tool comes with absolute not warranty
[ INFO  ] mestor01 Please check https://github.com/IBM/SpectrumScaleTools for details
[ INFO  ] mestor01 JSON files versions:
[ INFO  ] mestor01 	supported OS:		0.2
[ INFO  ] mestor01 	sysctl: 		0.5
[ INFO  ] mestor01 	packages: 		0.6
[ INFO  ] mestor01 	SAS adapters:		1.2
[ INFO  ] mestor01 	NIC adapters:		1.0
[ INFO  ] mestor01 	HW requirements:	1.0
[ INFO  ] mestor01 checking processor compatibility
[ INFO  ] mestor01 x86_64 processor is supported to run ECE
[ INFO  ] mestor01 checking socket count
[ INFO  ] mestor01 is Intel based
[ FATAL ] mestor01 has 4 sockets which is not verified to support ECE
[ INFO  ] mestor01 checking core count
[ FATAL ] mestor01 socket 0x0006 has 1 core[s]
[ FATAL ] mestor01 socket 0x0007 has 1 core[s]
[ FATAL ] mestor01 socket 0x0004 has 1 core[s]
[ FATAL ] mestor01 socket 0x0005 has 1 core[s]
[ WARN  ] mestor01 has a total of 4 core[s] which is less than 16 cores required to run ECE
[ INFO  ] mestor01 Red Hat Enterprise Linux Server 7.6 is a supported OS to run ECE
[ INFO  ] mestor01 checking packages install status
[ INFO  ] mestor01 installation status of dmidecode is as expected
[ INFO  ] mestor01 installation status of sg3_utils is as expected
[ INFO  ] mestor01 installation status of pciutils is as expected
[ INFO  ] mestor01 checking memory
[ FATAL ] mestor01 total memory is less than 60 GB required to run ECE
[ WARN  ] mestor01 not all 128 DIMM slot[s] are populated. This system has 127 empty DIMM slot[s]. This is not recommended to run ECE
[ INFO  ] mestor01 all populated DIMM slots have same memory size of 16384 MB
[ INFO  ] mestor01 checking SAS adapters
[ FATAL ] mestor01 does not have any SAS adapter supported by ECE. The disks under any SAS adapter in this system cannot be used by ECE
[ INFO  ] mestor01 checking NVMe devices
[ WARN  ] mestor01 no NVMe devices detected
[ FATAL ] mestor01 has no supported SAS adapter nor NVMe supported devices in this system
[ INFO  ] mestor01 checking NIC adapters
[ FATAL ] mestor01 does not have NIC adapter supported by ECE
[ INFO  ] mestor01 current active profile is throughput-performance
[ INFO  ] mestor01 tuned is matching the active profile
[ INFO  ] mestor01 checking sysctl settings
[ WARN  ] mestor01 net.ipv4.tcp_sack is 1 and should be 0
[ WARN  ] mestor01 net.core.rmem_default is 212992 and should be 16777216
[ WARN  ] mestor01 net.core.netdev_budget is 300 and should be 600
[ WARN  ] mestor01 net.core.wmem_default is 212992 and should be 16777216
[ WARN  ] mestor01 net.ipv4.tcp_slow_start_after_idle is 1 and should be 0
[ WARN  ] mestor01 net.ipv4.tcp_adv_win_scale is 1 and should be 2
[ WARN  ] mestor01 net.core.rmem_max is 212992 and should be 16777216
[ WARN  ] mestor01 sunrpc.tcp_slot_table_entriescurrent value does not exists
[ WARN  ] mestor01 net.core.somaxconn is 128 and should be 10000
[ WARN  ] mestor01 vm.min_free_kbytes is 67584 and should be 512000
[ WARN  ] mestor01 net.ipv4.tcp_tw_reuse is 0 and should be 1
[ WARN  ] mestor01 sunrpc.udp_slot_table_entriescurrent value does not exists
[ WARN  ] mestor01 net.ipv4.tcp_tw_recycle is 0 and should be 1
[ WARN  ] mestor01 kernel.shmmax is 18446744073692774399 and should be 13743895347
[ WARN  ] mestor01 net.ipv4.tcp_low_latency is 0 and should be 1
[ INFO  ] mestor01 net.ipv4.tcp_window_scaling it is set to the recommended value of 1
[ WARN  ] mestor01 net.core.optmem_max is 20480 and should be 16777216
[ WARN  ] mestor01 net.ipv4.tcp_max_syn_backlog is 512 and should be 8192
[ WARN  ] mestor01 net.ipv4.tcp_timestamps is 1 and should be 0
[ WARN  ] mestor01 net.ipv4.tcp_rmem is 4096 87380 6291456 and should be 4096 4224000 16777216
[ WARN  ] mestor01 net.ipv4.tcp_wmem is 4096 16384 4194304 and should be 4096 4224000 16777216
[ WARN  ] mestor01 net.core.wmem_max is 212992 and should be 16777216
[ WARN  ] mestor01 net.ipv4.tcp_syn_retries is 6 and should be 8
[ WARN  ] mestor01 net.core.netdev_max_backlog is 1000 and should be 300000
[ WARN  ] mestor01 kernel.sysrq is 16 and should be 1
[ INFO  ] mestor01 kernel.numa_balancing it is set to the recommended value of 0
[ FATAL ] mestor01 24 sysctl setting[s] need to be changed. Check information above this message

	Summary of this standalone run:
		Run started at 2019-11-28 10:46:54.722355
		ECE Readiness version 1.11
		Hostname: mestor01
		OS: Red Hat Enterprise Linux Server 7.6
		Architecture: x86_64
		Sockets: 4
		Cores per socket: [1, 1, 1, 1]
		Memory: 15 GBytes
		DIMM slots: 128
		DIMM slots in use: 1
		SAS HBAs in use:
		JBOD SAS HDD drives: 0
		JBOD SAS SSD drives: 0
		NVMe drives: 0
		HCAs in use:
		Link speed: NOT CHECKED
		Run ended at 2019-11-28 10:46:55.923375

		./10.10.12.92.json contains information about this run

[ FATAL ] mestor01 system cannot run IBM Spectrum Scale Erasure Code Edition
  ```
