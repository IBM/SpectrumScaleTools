This tool uses the JSON files from ece_os_readiness in [SpectrumScaleTools](https://github.com/IBM/SpectrumScaleTools). This tools with no warranty and it just a helper to asses the hardware for usage with Storage Scale Erasure Code Edition.

It does check for overall checks of homogeneity across the nodes. The assumption is that the nodes are belonging to the same recovery group (RG).

It does not check for the number of nodes, and that is in purpose. Please notice this tool is designed to run with the IBM Storage Scale install toolkit

```
# ./mor_overview.py -h
usage: mor_overview.py [-h] --json-files JSON_CSV_FILES_LIST [--no-checks]
                       [--path PATH/] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --json-files JSON_CSV_FILES_LIST
                        CSV JSON list of files to process
  --no-checks           Does not run any checks, just loads the files and
                        continues
  --path PATH/          Path ending with / where JSON files are located.
                        Defaults to local directory
  -v, --version         show program's version number and exit
  ```

  To run this tool you need to at least pass the mandatory parameter *--json-files JSON_CSV_FILES_LIST*

```
# python3 mor_overview.py --json-files 10.240.128.4.json,10.240.128.5.json,10.240.128.7.json
[ INFO  ]  Starting summary of individual ECE checks
[ INFO  ]  ece-bm-2 with IP address 10.240.128.4 passed the individual ECE checks
[ INFO  ]  ece-bm-3 with IP address 10.240.128.5 passed the individual ECE checks
[ INFO  ]  ece-bm-1 with IP address 10.240.128.7 passed the individual ECE checks
[ INFO  ]  Individual ECE checks passed on all configured ECE nodes
[ INFO  ]  Starting overall ECE checks version 1.81
[ INFO  ]  Completed overall ECE checks
[ INFO  ]  All ECE nodes have the same processor architecture
[ INFO  ]  All ECE nodes have the same number of sockets
[ INFO  ]  All ECE nodes have the same number of cores per socket
[ INFO  ]  All ECE nodes have the same number DIMM slots and modules
[ INFO  ]  All ECE nodes have the same system memory
[ INFO  ]  All ECE nodes have the same NIC model
[ INFO  ]  All ECE nodes have the same network link speed
[ INFO  ]  All ECE nodes have the same SAS model
[ INFO  ]  All ECE nodes have NVMe drives or all ECE nodes have no NVMe drives
[ INFO  ]  All ECE nodes have the same number of NVMe drives
[ INFO  ]  There are 24 NVMe drive[s] that can be used by the ECE cluster
[ INFO  ]  All ECE nodes have NVMe drives that have unique euids/nguids.
[ INFO  ]  All ECE nodes have SSD drives or all ECE nodes have no SSD drives
[ INFO  ]  All ECE nodes have the same number of SSD drives
[ INFO  ]  There are no SSD drives that can be used by ECE
[ INFO  ]  All ECE nodes have HDD drives or all ECE nodes have no HDD drives
[ INFO  ]  All ECE nodes have the same number of HDD drives
[ INFO  ]  There are no HDD drives that can be used by ECE
[ INFO  ]  There are 12 or more drives of one technology that can be used by the ECE cluster
[ INFO  ]  There are 24 drive[s] that can be used by the ECE cluster, the maximum number of drives per Recovery Group is 512
[ INFO  ]  All nodes have unique serial numbers
[ INFO  ]  All ECE checks passed, installation can continue
```
