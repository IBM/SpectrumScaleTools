This tool assesses the readiness of a single node to install IBM Storage Scale Erasure Code Edition (ECE). This tool only checks for requirement of a system that can run ECE, no other software or middleware on top in the same server.

Run this tool before installing ECE with the IBM Storage Scale toolkit, it is used by the toolkit to do a more comprehensive node checking from a cluster perspective, this tool checks at node level. Each run generates a JSON file with name IP_ADDRESS.json where data is saved. In standalone mode this file is only for reference.

**IMPORTANT**
This tool does not overrule the official documentation of the product. The requirements stated on the official documentation as "Minimum hardware requirements and precheck" in https://www.ibm.com/docs/en/storage-scale-ece

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
# python3 mor.py -h
usage: mor.py [-h] [--FIPS] --ip IPv4_ADDRESS [--path PATH/] [--no-cpu-check]
              [--no-md5-check] [--no-mem-check] [--no-os-check]
              [--no-packages-check] [--no-net-check] [--no-storage-check]
              [--no-tuned-check] [--allow-sata] [--toolkit] [-V] [-v]

optional arguments:
  -h, --help           show this help message and exit
  --FIPS               Does not run parts of the code that cannot run on FIPS
                       systems. The run with this parameter is not complete
                       and cannot be used for acceptance.
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
  --no-tuned-check     Does not run tuned checks
  --allow-sata         EXPERIMENTAL: To do checks on SATA drives. Do NOT use
                       for real checks
  --toolkit            To indicate is being run from IBM Storage Scale
                       install toolkit
  -V, --version        show program's version number and exit
  -v, --verbose        Shows debug messages on console
```

  Use --no-*-check parameters to skip certain item checking. In order to install ECE, all the tests must pass on all nodes. You can additionally gather the JSON output files and run ece_os_overview.

  A "good enough" example is as follows:

  ```
# python3 mor.py --ip 10.168.3.101
[ INFO  ] c72f3u01 IBM Storage Scale Erasure Code Edition OS readiness version 1.71
[ INFO  ] c72f3u01 This tool comes with absolute not warranty
[ INFO  ] c72f3u01 Please check https://github.com/IBM/SpectrumScaleTools for details
[ INFO  ] c72f3u01 JSON files versions:
[ INFO  ] c72f3u01 	supported OS:		1.7
[ INFO  ] c72f3u01 	packages: 		1.4
[ INFO  ] c72f3u01 	SAS adapters:		1.7
[ INFO  ] c72f3u01 	NIC adapters:		1.1
[ INFO  ] c72f3u01 	HW requirements:	1.7
[ INFO  ] c72f3u01 the tool is being run as root
[ INFO  ] c72f3u01 checking processor compatibility
[ INFO  ] c72f3u01 x86_64 processor is supported to run ECE
[ INFO  ] c72f3u01 checking socket count
[ INFO  ] c72f3u01 is Intel based
[ INFO  ] c72f3u01 has 2 socket[s] which complies with the requirements to support ECE
[ INFO  ] c72f3u01 checking core count
[ INFO  ] c72f3u01 socket 0x0053 has 28 core[s]
[ INFO  ] c72f3u01 socket 0x0057 has 28 core[s]
[ INFO  ] c72f3u01 has a total of 56 cores which complies with the requirements to support ECE
[ INFO  ] c72f3u01 Red Hat Enterprise Linux 8.4 is a supported OS to run ECE
[ INFO  ] c72f3u01 checking package installation status
[ INFO  ] c72f3u01 has dmidecode installed as expected
[ INFO  ] c72f3u01 has pciutils installed as expected
[ INFO  ] c72f3u01 has sg3_utils installed as expected
[ INFO  ] c72f3u01 has numactl installed as expected
[ INFO  ] c72f3u01 has numactl-libs installed as expected
[ INFO  ] c72f3u01 has tuned installed as expected
[ INFO  ] c72f3u01 does not have MegaCli installed as expected
[ INFO  ] c72f3u01 has sqlite installed as expected
[ INFO  ] c72f3u01 checking memory
[ INFO  ] c72f3u01 has a total of 251.29 GiB memory which is sufficient to run ECE
[ WARN  ] c72f3u01 has 8(16 in total) DIMM slot[s] which is not optimal when NVMe drive was used
[ INFO  ] c72f3u01 all populated DIMM slots have same size
[ INFO  ] c72f3u01 SAS TOOL:/opt/MegaRAID/storcli/storcli64
[ INFO  ] c72f3u01 checking SAS adapters
[ WARN  ] c72f3u01 has a non tested SAS adapter
[ INFO  ] c72f3u01 has a fabric SAS speed of SAS-12G for its fabric. Please rememeber to run the Storage acceptance tool that can be found at ece_storage_readiness in https://github.com/IBM/SpectrumScaleTools
[ INFO  ] c72f3u01 checking if software required by SAS was installed
[ INFO  ] c72f3u01 checking package installation status
[ INFO  ] c72f3u01 has storcli installed as expected
[ INFO  ] c72f3u01 has 60 HDD drive[s] on the SAS adapter the same size that ECE can use
[ INFO  ] c72f3u01 all SAS drives have Volatile Write Cache disabled
[ WARN  ] c72f3u01 has 0 SSD drive[s] that ECE can use
[ INFO  ] c72f3u01 checking NVMe drive
[ INFO  ] c72f3u01 has a total of 4 NVMe drive[s] but more checks are required
[ INFO  ] c72f3u01 checking if software required by NVMe drive was installed
[ INFO  ] c72f3u01 checking package installation status
[ INFO  ] c72f3u01 has nvme-cli installed as expected
[ INFO  ] c72f3u01 all NVMe drives have the same size
[ INFO  ] c72f3u01 all NVME drives have Volatile Write Cache disabled
[ INFO  ] c72f3u01 all NVMe drives have the same LBA size
[ INFO  ] c72f3u01 all NVMe drives have the same metadata size
[ INFO  ] c72f3u01 all NVMe drives have 0 metadata size
[ INFO  ] c72f3u01 all NVMe drives have unique IDs
[ INFO  ] c72f3u01 has at least one SSD or NVMe device that ECE can use. This is required to run ECE
[ INFO  ] c72f3u01 has 64 drives that ECE can use
[ INFO  ] c72f3u01 checking NIC adapters
[ INFO  ] c72f3u01 has ConnectX-5 adapter which is supported by ECE
[ INFO  ] c72f3u01 checking 10.168.3.101 device and link speed
[ INFO  ] c72f3u01 the IP address 10.168.3.101 is found on device ib1
[ INFO  ] c72f3u01 interface ib1 has a link of 100000 Mb/s. Which is supported to run ECE
[ INFO  ] c72f3u01 current active profile is storagescale-ece
[ INFO  ] c72f3u01 tuned is matching the active profile
[ INFO  ] c72f3u01 python 3 YAML module found

	Summary of this standalone run:
		Run started at 2023-04-06 03:05:55.171947
		ECE Readiness version 1.71
		Hostname: c72f3u01
		OS: Red Hat Enterprise Linux 8.4
		Architecture: x86_64
		Sockets: 2
		Cores per socket: [28, 28]
		Memory: 251.29 GiBytes
		DIMM slots: 16
		DIMM slots in use: 8
		SAS HBAs in use: NOT TESTED
		JBOD SAS HDD drives: 60
		JBOD SAS SSD drives: 0
		HCAs in use: ConnectX-5
		NVMe drives: 4
		Link speed: 100000
		Run ended at 2023-04-06 03:06:35.504791

		./10.168.3.101.json contains information about this run

[ INFO  ] c72f3u01 can run IBM Storage Scale Erasure Code Edition
  ```

  A failed example is as follows:

  ```
# ./mor.py --ip 10.168.2.17
[ INFO  ] c72f4m5u17 IBM Storage Scale Erasure Code Edition OS readiness version 1.71
[ INFO  ] c72f4m5u17 This tool comes with absolute not warranty
[ INFO  ] c72f4m5u17 Please check https://github.com/IBM/SpectrumScaleTools for details
[ INFO  ] c72f4m5u17 JSON files versions:
[ INFO  ] c72f4m5u17 	supported OS:		1.7
[ INFO  ] c72f4m5u17 	packages: 		1.4
[ INFO  ] c72f4m5u17 	SAS adapters:		1.7
[ INFO  ] c72f4m5u17 	NIC adapters:		1.1
[ INFO  ] c72f4m5u17 	HW requirements:	1.7
[ INFO  ] c72f4m5u17 the tool is being run as root
[ INFO  ] c72f4m5u17 checking processor compatibility
[ INFO  ] c72f4m5u17 x86_64 processor is supported to run ECE
[ INFO  ] c72f4m5u17 checking socket count
[ INFO  ] c72f4m5u17 is Intel based
[ INFO  ] c72f4m5u17 has 2 socket[s] which complies with the requirements to support ECE
[ INFO  ] c72f4m5u17 checking core count
[ INFO  ] c72f4m5u17 socket 0x0048 has 10 core[s]
[ INFO  ] c72f4m5u17 socket 0x0044 has 10 core[s]
[ INFO  ] c72f4m5u17 has a total of 20 cores which complies with the requirements to support ECE
[ INFO  ] c72f4m5u17 Red Hat Enterprise Linux Server 7.8 is a supported OS to run ECE
[ INFO  ] c72f4m5u17 checking package installation status
[ INFO  ] c72f4m5u17 has sqlite installed as expected
[ INFO  ] c72f4m5u17 has numactl-libs installed as expected
[ INFO  ] c72f4m5u17 has numactl installed as expected
[ INFO  ] c72f4m5u17 has sg3_utils installed as expected
[ INFO  ] c72f4m5u17 does not have MegaCli installed as expected
[ INFO  ] c72f4m5u17 has tuned installed as expected
[ INFO  ] c72f4m5u17 has dmidecode installed as expected
[ INFO  ] c72f4m5u17 has pciutils installed as expected
[ INFO  ] c72f4m5u17 checking memory
[ INFO  ] c72f4m5u17 has a total of 125.0 GiB memory which is sufficient to run ECE
[ WARN  ] c72f4m5u17 has 4(24 in total) DIMM slot[s] which is not optimal when NVMe drive was used
[ INFO  ] c72f4m5u17 all populated DIMM slots have same size
[ INFO  ] c72f4m5u17 SAS TOOL:/opt/MegaRAID/storcli/storcli64
[ INFO  ] c72f4m5u17 checking SAS adapters
[ INFO  ] c72f4m5u17 has a fabric SAS speed of SAS-12G for its fabric. Please rememeber to run the Storage acceptance tool that can be found at ece_storage_readiness in https://github.com/IBM/SpectrumScaleTools
[ INFO  ] c72f4m5u17 has MegaRAID Tri-Mode SAS3516 adapter which is tested by IBM. The disks under this SAS adapter could be used by ECE
[ INFO  ] c72f4m5u17 checking if software required by SAS was installed
[ INFO  ] c72f4m5u17 checking package installation status
[ INFO  ] c72f4m5u17 has storcli installed as expected
[ INFO  ] c72f4m5u17 has 3 HDD drive[s] on the SAS adapter the same size that ECE can use
[ FATAL ] c72f4m5u17 134:7 has Write Cache Enabled. This is not supported by ECE
[ FATAL ] c72f4m5u17 134:6 has Write Cache Enabled. This is not supported by ECE
[ FATAL ] c72f4m5u17 134:5 has Write Cache Enabled. This is not supported by ECE
[ WARN  ] c72f4m5u17 has 4 SATA SSD drive[s] on the SAS adapter. SATA drives are not supported by ECE. Do not use them for ECE
[ WARN  ] c72f4m5u17 has 0 SSD drive[s] that ECE can use
[ INFO  ] c72f4m5u17 checking NVMe drive
[ INFO  ] c72f4m5u17 has a total of 2 NVMe drive[s] but more checks are required
[ INFO  ] c72f4m5u17 checking if software required by NVMe drive was installed
[ INFO  ] c72f4m5u17 checking package installation status
[ INFO  ] c72f4m5u17 has nvme-cli installed as expected
[ INFO  ] c72f4m5u17 all NVMe drives have the same size
[ INFO  ] c72f4m5u17 all NVME drives have Volatile Write Cache disabled
[ INFO  ] c72f4m5u17 all NVMe drives have the same LBA size
[ INFO  ] c72f4m5u17 all NVMe drives have the same metadata size
[ INFO  ] c72f4m5u17 all NVMe drives have 0 metadata size
[ INFO  ] c72f4m5u17 all NVMe drives have unique IDs
[ INFO  ] c72f4m5u17 has at least one SSD or NVMe device that ECE can use. This is required to run ECE
[ INFO  ] c72f4m5u17 has 5 drives that ECE can use
[ INFO  ] c72f4m5u17 checking NIC adapters
[ INFO  ] c72f4m5u17 has ConnectX-4 adapter which is supported by ECE
[ INFO  ] c72f4m5u17 checking 10.168.2.17 device and link speed
[ INFO  ] c72f4m5u17 the IP address 10.168.2.17 is found on device ib0
[ INFO  ] c72f4m5u17 interface ib0 has a link of 100000 Mb/s. Which is supported to run ECE
[ INFO  ] c72f4m5u17 current active profile is storagescale-ece
[ INFO  ] c72f4m5u17 tuned is matching the active profile
[ INFO  ] c72f4m5u17 python 3 YAML module found

	Summary of this standalone run:
		Run started at 2023-04-06 03:03:31.265245
		ECE Readiness version 1.71
		Hostname: c72f4m5u17
		OS: Red Hat Enterprise Linux Server 7.8
		Architecture: x86_64
		Sockets: 2
		Cores per socket: [10, 10]
		Memory: 125.0 GiBytes
		DIMM slots: 24
		DIMM slots in use: 4
		SAS HBAs in use: MegaRAID Tri-Mode SAS3516
		JBOD SAS HDD drives: 3
		JBOD SAS SSD drives: 0
		HCAs in use: ConnectX-4
		NVMe drives: 2
		Link speed: 100000
		Run ended at 2023-04-06 03:03:38.310555

		./10.168.2.17.json contains information about this run

[ FATAL ] c72f4m5u17 cannot run IBM Storage Scale Erasure Code Edition
  ```
