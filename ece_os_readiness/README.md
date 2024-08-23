This tool assesses the readiness of a single server to install IBM Storage Scale Erasure Code Edition (ECE). It only checks if a server could meet the requirements to run ECE.

Run this tool before installing ECE with the IBM Storage Scale toolkit, it is used by the toolkit to do a more comprehensive server checking from a cluster perspective, this tool checks at node level. Each run generates a JSON file IPv4_ADDRESS.json to save the check result in standalone mode.

**IMPORTANT**
This tool does not overrule the official documentation of the product. The requirements stated on the official documentation as "Minimum hardware requirements and precheck" in https://www.ibm.com/docs/en/storage-scale-ece

**Known limitations**
- This tool can only be executed with Python3.6 and later Python versions.

**PREREQUISITES:**
Before running this tool you **must** install the software prerequisites. They are:
 * RPM packages listed in packages.json and marked as "OK".
 * python3-dmidecode and python3-pyyaml. For pyyaml, please check [pyyaml documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
 * nvme-cli RPM package if the server to be checked has NVME drive.
 * storcli if the server to be checked has SCSI controller.
 * MegaCli is not supported.


Usage:
```
# python3 mor.py -h
usage: mor.py [-h] --ip IPv4_ADDRESS [--path PATH] [--FIPS] [--no-md5-check]
              [--no-cpu-check] [--no-os-check] [--no-pkg-check]
              [--no-mem-check] [--no-stor-check] [--no-net-check]
              [--no-tuned-check] [--allow-sata] [--toolkit] [-V] [-v]

optional arguments:
  -h, --help         show this help message and exit
  --ip IPv4_ADDRESS  local IPv4 for NSD (Network Shared Disks)
  --path PATH        where json files are located. Default is current
                     directory
  --FIPS             run this tool with FIPS (Federal Information Processing
                     Standards) mode. The FIPS mode cannot be used for
                     acceptance
  --no-md5-check     skip JSON file check
  --no-cpu-check     skip CPU check
  --no-os-check      skip OS check
  --no-pkg-check     skip required package check
  --no-mem-check     skip memory check
  --no-stor-check    skip storage check
  --no-net-check     skip network check
  --no-tuned-check   skip tuned check
  --allow-sata       EXPERIMENTAL: Check SATA storage device
  --toolkit          use this option when IBM Storage Scale install-toolkit
                     runs the tool
  -V, --version      show program's version number and exit
  -v, --verbose      show debug messages on console
```

Argument --ip is required. Pass the local IPv4 address which will be used by the NSD (Network Shared Disks) traffic.
Use --no-*-check arguments to skip certain checkings. In order to install ECE, all storage servers must pass all checkings.

A successful example may look like:

```
# python3 mor.py --ip 192.168.100.10
[ INFO  ] ece10-hs IBM Storage Scale Erasure Code Edition (ECE) OS readiness version: 2.00
[ INFO  ] ece10-hs This precheck tool with absolutely no warranty
[ INFO  ] ece10-hs For more information, please check https://github.com/IBM/SpectrumScaleTools
[ INFO  ] ece10-hs JSON file versions:
[ INFO  ] ece10-hs 	supported OS: 		2.0
[ INFO  ] ece10-hs 	packages: 		1.5
[ INFO  ] ece10-hs 	SAS adapters: 		1.8
[ INFO  ] ece10-hs 	NIC adapters: 		1.1
[ INFO  ] ece10-hs 	HW requirements: 	1.8
[ INFO  ] ece10-hs is running with 'root' user
[ INFO  ] ece10-hs is checking system processor
[ INFO  ] ece10-hs has x86_64 processor which is supported to run ECE
[ INFO  ] ece10-hs is checking CPU
[ INFO  ] ece10-hs has an Intel CPU socket with handle 0x003F. It has 8 core[s]
[ INFO  ] ece10-hs has an Intel CPU socket with handle 0x0043. It has 8 core[s]
[ INFO  ] ece10-hs has 2 CPU socket[s] which complies with ECE requirement
[ INFO  ] ece10-hs has a total of 16 cores that comply with ECE requirement
[ INFO  ] ece10-hs is running Red Hat Enterprise Linux 8.6 (Ootpa)
[ INFO  ] ece10-hs is checking package installation state
[ INFO  ] ece10-hs has dmidecode installed, which is as expected
[ INFO  ] ece10-hs has pciutils installed, which is as expected
[ INFO  ] ece10-hs has sg3_utils installed, which is as expected
[ INFO  ] ece10-hs has numactl installed, which is as expected
[ INFO  ] ece10-hs has numactl-libs installed, which is as expected
[ INFO  ] ece10-hs has tuned installed, which is as expected
[ INFO  ] ece10-hs does not have MegaCli installed, which is as expected
[ INFO  ] ece10-hs has sqlite installed, which is as expected
[ INFO  ] ece10-hs is querying system serial number
[ INFO  ] ece10-hs is checking memory
[ WARN  ] ece10-hs has 6/24(populated/total) DIMM slot[s] which is not optimal if NVMe drive was used
[ INFO  ] ece10-hs Each in-use memory slot is populated with 32 GB memory module
[ INFO  ] ece10-hs has a total of 188.32 GiB memory which is sufficient to run ECE
[ INFO  ] ece10-hs is checking SCSI controller
[ INFO  ] ece10-hs has following SCSI controller tested by IBM
[ INFO  ] ece10-hs Broadcom / LSI MegaRAID Tri-Mode SAS3516 (rev 01)
[ INFO  ] ece10-hs disks attached to above SCSI controller can be used by ECE
[ WARN  ] ece10-hs has following SCSI controllers NOT tested by IBM
[ WARN  ] ece10-hs Intel Corporation C620 Series Chipset Family SSATA Controller [AHCI mode] (rev 09)
[ WARN  ] ece10-hs Intel Corporation C620 Series Chipset Family SATA Controller [AHCI mode] (rev 09)
[ WARN  ] ece10-hs disks attached to above 2 SCSI controllers may not be used by ECE
[ INFO  ] ece10-hs sets MegaRAID tool to '/opt/MegaRAID/storcli/storcli64'
[ INFO  ] ece10-hs MegaRAID tool is available
[ INFO  ] ece10-hs MegaRAID tool is querying the device information it manages...
[ INFO  ] ece10-hs has 1 Controller managed by the MegaRAID tool
[ WARN  ] ece10-hs lspci detected 3 SAS/SATA controller[s] but MegaRAID managed 1 controller[s]
[ INFO  ] ece10-hs has 1 SAS-12G Controller[s]
[ INFO  ] ece10-hs is checking SAS device
[ WARN  ] ece10-hs has /dev/sdj mounted to /locallogs that cannot be used by ECE
[ INFO  ] ece10-hs has SAS HDD /dev/sda, /dev/sdb, /dev/sdc, /dev/sdd, /dev/sde, /dev/sdg, /dev/sdi, /dev/sdl that can be used by ECE
[ INFO  ] ece10-hs has /dev/sda, /dev/sdb, /dev/sdc, /dev/sdd, /dev/sde, /dev/sdg, /dev/sdi, /dev/sdl with Write Cache Disabled
[ INFO  ] ece10-hs does not have any proper SAS SSD to be used by ECE
[ INFO  ] ece10-hs It seems all SAS storage devices are managed by the MegaRAID tool
[ INFO  ] ece10-hs has a total of 8 SAS HDD[s] that can be used by ECE
[ INFO  ] ece10-hs is checking NVMe drive
[ INFO  ] ece10-hs has a total of 2 NVMe drives
[ INFO  ] ece10-hs is checking package required by NVMe drive
[ INFO  ] ece10-hs has 'nvme-cli' installed
[ INFO  ] ece10-hs is getting information of NVMe drive[s]
[ INFO  ] ece10-hs all NVMe drives have the same size
[ WARN  ] ece10-hs has /dev/nvme0n1 whose Volatile Write Cache field is unsupported. Please contract the vendor
[ WARN  ] ece10-hs has /dev/nvme1n1 whose Volatile Write Cache field is unsupported. Please contract the vendor
[ WARN  ] ece10-hs All NVMe drives have Volatile Write Cache Enabled (VWCE) or unknown VWCE state
[ INFO  ] ece10-hs all NVMe drives have the same in-use LBA ds: 12
[ INFO  ] ece10-hs all NVMe drives have the same in-use LBA ms: 0
[ INFO  ] ece10-hs all NVMe drives have their unique IDs
[ INFO  ] ece10-hs has a total of 10 disk[s] that can be used by ECE
[ INFO  ] ece10-hs has IP address 192.168.100.10 set to network interface: ens6
[ INFO  ] ece10-hs is checking network device
[ INFO  ] ece10-hs has following network controller tested by IBM
[ INFO  ] ece10-hs Mellanox Technologies MT27700 Family [ConnectX-4]
[ WARN  ] ece10-hs has following network controllers NOT tested by IBM
[ WARN  ] ece10-hs Intel Corporation Ethernet Connection X722 for 1GbE (rev 09)
[ WARN  ] ece10-hs Intel Corporation Ethernet Connection X722 for 1GbE (rev 09)
[ INFO  ] ece10-hs has ens6 with speed 100000 Mb/s. It complies with ECE required 24000 Mb/s
[ INFO  ] ece10-hs is checking tuned profile
[ INFO  ] ece10-hs has Current active profile: storagescale-ece
[ INFO  ] ece10-hs current system settings match the preset profile
[ INFO  ] ece10-hs is checking Python3 YAML
[ INFO  ] ece10-hs has Python3 YAML module installed

	Summary of this standalone instance:
		Started at 2024-06-05 09:54:43.992
		OS Readiness version 2.00
		Hostname: ece10-hs
		OS: Red Hat Enterprise Linux 8.6 (Ootpa)
		Processor architecture: x86_64
		CPU sockets: 2
		CPU cores per socket: [8, 8]
		Memory size in total: 188 GiBytes
		DIMM slots in total: 24
		DIMM slots in use:   6
		DIMM slots unused:   18
		SCSI controller:
		    Broadcom / LSI MegaRAID Tri-Mode SAS3516 (rev 01)
		JBOD SAS HDD device: 8
		JBOD SAS SSD device: 0
		NVMe drive:          2
		Network controller:
		    Mellanox Technologies MT27700 Family [ConnectX-4]
		Link speed of given IPv4: 100000 Mb/s
		Ended at 2024-06-05 09:54:50.957

[ INFO  ] ece10-hs saved detailed information of this instance to ./192.168.100.10.json
[ INFO  ] ece10-hs can run IBM Storage Scale Erasure Code Edition


```

A failed example might look like:

```
# python3 mor.py --ip 192.168.100.10 --no-md5-check --no-cpu-check --no-os-check --no-pkg-check --no-mem-check --no-stor-check --no-net-check --no-tuned-check --allow-sata
[ INFO  ] ece10-hs IBM Storage Scale Erasure Code Edition (ECE) OS readiness version: 2.00
[ INFO  ] ece10-hs This precheck tool with absolutely no warranty
[ INFO  ] ece10-hs For more information, please check https://github.com/IBM/SpectrumScaleTools
[ INFO  ] ece10-hs JSON file versions:
[ INFO  ] ece10-hs 	supported OS: 		2.0
[ INFO  ] ece10-hs 	packages: 		1.5
[ INFO  ] ece10-hs 	SAS adapters: 		1.8
[ INFO  ] ece10-hs 	NIC adapters: 		1.1
[ INFO  ] ece10-hs 	HW requirements: 	1.8
[ INFO  ] ece10-hs is running with 'root' user
[ FATAL ] ece10-hs has skipped json file MD5 checksum checking
[ FATAL ] ece10-hs has skipped CPU checking
[ FATAL ] ece10-hs has skipped OS checking
[ FATAL ] ece10-hs has skipped package checking
[ INFO  ] ece10-hs is querying system serial number
[ FATAL ] ece10-hs has skipped memory checking
[ FATAL ] ece10-hs has skipped storage checking
[ FATAL ] ece10-hs has skipped network checking
[ FATAL ] ece10-hs has skipped tuned checking
[ INFO  ] ece10-hs is checking Python3 YAML
[ INFO  ] ece10-hs has Python3 YAML module installed

	Summary of this standalone instance:
		Started at 2024-06-24 15:24:36.916
		OS Readiness version 2.00
		Hostname: ece10-hs
		OS: Unknown
		Processor architecture: Unknown
		CPU sockets: 0
		CPU cores per socket: []
		Memory size in total: 0 GiBytes
		DIMM slots in total: 0
		DIMM slots in use:   0
		DIMM slots unused:   0
		SCSI controller:
		    No supported SCSI controller
		JBOD SAS HDD device: 0
		JBOD SAS SSD device: 0
		NVMe drive:          0
		Network controller:
		    No explicitly supported network controller
		Link speed of given IPv4: Unknown
		Ended at 2024-06-24 15:24:37.062

[ INFO  ] ece10-hs saved detailed information of this instance to ./192.168.100.10.json
[ FATAL ] ece10-hs is missing some checks. The precheck tool can NOT claim this system could run IBM Storage Scale Erasure Code Edition
[ FATAL ] ece10-hs cannot run IBM Storage Scale Erasure Code Edition


```
