This tool uses the JSON files from [SpectrumScale_ECE_OS_READINESS](https://github.com/IBM/SpectrumScale_ECE_OS_READINESS). This tools with no warranty and it just a helper to asses the hardware for usage with Spectrum Scale Erasure Code Edition.

It does check for overall checks of homogeneity across the nodes. The assumption is that the nodes are belonging to the same recovery group (RG).

It does not check for the number of nodes, and that is in purpose. Please notice this tool is designed to run with the Spectrum Scale install toolkit

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
# ./mor_overview.py --json-files 10.168.2.17.json,10.168.2.18.json,10.168.2.19.json,10.168.2.20.json
[ INFO  ]  Starting summary of individual ECE checks
[ INFO  ]  c72f4m5u17-ib0 with IP address 10.168.2.17 passed the individual ECE checks
[ INFO  ]  c72f4m5u18-ib0 with IP address 10.168.2.18 passed the individual ECE checks
[ INFO  ]  c72f4m5u19-ib0 with IP address 10.168.2.19 passed the individual ECE checks
[ INFO  ]  c72f4m5u20-ib0 with IP address 10.168.2.20 passed the individual ECE checks
[ INFO  ]  Individual ECE checks passed on all configured ECE nodes
[ INFO  ]  Starting overall ECE checks version 1.1
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
[ INFO  ]  There are 8 NVMe drive[s] that can be used by the ECE cluster
[ INFO  ]  All ECE nodes have SSD drives or all ECE nodes have no SSD drives
[ INFO  ]  All ECE nodes have the same number of SSD drives
[ INFO  ]  There are no SSD drives that can be used by ECE
[ INFO  ]  All ECE nodes have HDD drives or all ECE nodes have no HDD drives
[ INFO  ]  All ECE nodes have the same number of HDD drives
[ INFO  ]  There are 12 HDD drive[s] that can be used by the ECE cluster
[ INFO  ]  There are 12 or more drives of one technology that can be used by the ECE cluster
[ INFO  ]  There are 20 drive[s] that can be used by the ECE cluster, the maximum number of drives per Recovery Group is 512
[ INFO  ]  All ECE checks passed, installation can continue
```
