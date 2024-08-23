This tool uses the JSON files from ece_os_readiness in [SpectrumScaleTools](https://github.com/IBM/SpectrumScaleTools) to do the overview precheck. It simply helps to check the servers on which IBM Storage Scale Erasure Code Edition would be installed.

**Known limitations**
This tool checks the homogeneity of all storage servers. The precondition is that all servers will be configured to the same recovery group (RG).

Usage:
```
# python3 mor_overview.py -h
usage: mor_overview.py [-h] --json-files JSON_FILES [--no-check] [--path PATH]
                       [-v]

optional arguments:
  -h, --help            show this help message and exit
  --json-files JSON_FILES
                        Comma-separated Json files
  --no-check            Skip all homogeneity checks
  --path PATH           where JSON files are located. Default is current
                        directory
  -v, --version         show program's version number and exit
```

A successful example may look like:

```
# python3 mor_overview.py --json-files 192.168.100.9.json,192.168.100.10.json,192.168.100.11.json
[ INFO  ] IBM Storage Scale Erasure Code Edition (ECE) OS overview version: 1.90
[ INFO  ] Summarize separate storage server checks
[ INFO  ] All nodes marked the node ready state as True
[ INFO  ] All nodes have the same processor architecture: x86_64
[ INFO  ] All nodes have the same CPU socket number: 2
[ INFO  ] All nodes have the same CPU core distribution: [8, 8]
[ INFO  ] All nodes have the same vacant DIMM slot number: 6
[ INFO  ] All nodes have the same memory size: 188.32 GiB
[ INFO  ] All nodes have the same network controller: Mellanox Technologies MT27700 Family [ConnectX-4]
[ INFO  ] All nodes have the same to-be-used network interface link speed: 100000 Mb/s
[ INFO  ] All nodes have the same SCSI controller: Broadcom / LSI MegaRAID Tri-Mode SAS3516 (rev 01)
[ INFO  ] All nodes have the same NVMe device number: 2
[ INFO  ] This cluster has a total NVMe device number: 6
[ INFO  ] All NVMe drives in this cluster have unique euis and nguids
[ INFO  ] All nodes hit SSD error. They may not have available SSD device
[ INFO  ] All nodes have the same HDD device number: 8
[ INFO  ] This cluster has a total HDD device number: 24
[ INFO  ] All HDD devices in this cluster have unique wwns
[ INFO  ] All nodes have the same total storage device number: 10
[ INFO  ] This cluster has a total storage device number: 30
[ INFO  ] All nodes have unique serial number
[ INFO  ] ECE overview checks are completed
[ INFO  ] All ECE overview checks passed. Installation continues
```

