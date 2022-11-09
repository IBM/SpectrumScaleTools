This tool calculates the effective capacity of Spectrum Scale Native RAID systems. It is an estimation and actual figures could differ from the calculated ones. Be prepared for 1% deviations when using this tool. As a reminder, this tool comes with not warranty of any kind.

**TODO:**
 * Further tests to compare from real capacity vs calculated to tune the tool

**PREREQUISITES:** Before running this tool you **must** fulfill the prerequisites:
 * python3 installed in the system
 * User must have understanding of Spectrum Scale Native RAID

The tool requires four parameters to be passed on when invoking them:
 * -n or --node-count ->  Number of storage nodes. For ESS this will be 2. For ECE it should be between 4 and 32.
 * -p or --pdisk-per-node -> Number of identically sized pdisks per storage node.
 * -e or --erasure-code -> Erasure code for vdisks, from ['4+2p', '8+3p', '8+2p','4+3p']
 * Capacity of each pdisk either on GiB (-s or --pdisk-size-gib) or TB (-t or --pdisk-size-tb)



The help includes the description of the optional parameters

```
$ ./gnr_capacity_estimator.py -h

IBM Spectrum Scale Native RAID Estimator version 1.2
This tool comes with no warranty of any kind

Please check https://github.com/IBM/SpectrumScaleTools for updates and other information

usage: gnr_capacity_estimator.py [-h] -n NODE_COUNT -p PDISK_PER_NODE
                                 [-s PDISK_SIZE_GIB] [-t PDISK_SIZE_TB] -e
                                 ERASURE_CODE [-b BLOCK_SIZE] [-d DISK_TYPE]
                                 [-x] [-j] [--spare-drives SPARE_DRIVES]
                                 [--set-size SET_SIZE] [-v]

Spectrum Scale RAID Capacity Estimator

optional arguments:
  -h, --help            show this help message and exit
  -n NODE_COUNT, --node-count NODE_COUNT
                        Number of storage nodes. For ESS this will always be
                        2. For ECE it should be between 4 and 32.
  -p PDISK_PER_NODE, --pdisk-per-node PDISK_PER_NODE
                        Number of identically sized pdisks per storage node.
  -s PDISK_SIZE_GIB, --pdisk-size-gib PDISK_SIZE_GIB
                        (Optional) Size of each pdisk in GiB (2^^30 bytes).
  -t PDISK_SIZE_TB, --pdisk-size-tb PDISK_SIZE_TB
                        Size of each pdisk in TB (decimal).
  -e ERASURE_CODE, --erasure-code ERASURE_CODE
                        Erasure code for vdisks, from dict_keys(['4+2p',
                        '4+3p', '8+2p', '8+3p']).
  -b BLOCK_SIZE, --block-size BLOCK_SIZE
                        Blocksize, in MiB, from [1, 2, 4, 8, 16], (default 4).
  -d DISK_TYPE, --disk-type DISK_TYPE
                        Disk type, from ['hdd', 'ssd'], both NVMe and SAS SSD
                        are considered 'ssd' drives (default 'hdd').
  -x, --exclude-loghome-vdisks
                        Exclude loghome vdisks in sizing estimate.
  -j, --json-format     Output results in json format.
  --spare-drives SPARE_DRIVES
                        (Optional) If specified use this value as the number
                        of drives of spare capacity rather than calculating
                        based on the number of nodes in the recovery group.
  --set-size SET_SIZE   (Optional) Specifies the set size of a vdisk set
                        definition. It defaults to 100 per cent. The value
                        passed must be between 10 and 100
  -v, --verbose         Verbose output.

```

As example to run an estimation of an ECE system of 12 nodes that have 12 4 TB drives each and we plan to use 8+2p as erasure code:

```
# ./gnr_capacity_estimator.py --node-count 12 --pdisk-per-node 12 --pdisk-size-tb 4 --erasure-code 8+2p
```

The output for the above run is

```
IBM Spectrum Scale Native RAID Estimator version 1.0
This tool comes with no warranty of any kind

Please check https://github.com/IBM/SpectrumScaleTools for updates or other information

Input Parameter Summary:
------------------------
Node count:                                                   12
Pdisks per node:                                              12
Erasure code:                                               8+2p
Pdisk size (TB):                                            4.00
Block size (MiB):                                              4
Disk type:                                                   hdd
Checksum granularity (KiB):                                   32
Include loghome vdisks?                                     True

Spectrum Scale RAID vdisk and file system summary:
----------------------------------
Total number of drives                                       144
Spare capacity in number of drives:                            6
Total raw capacity (GiB):                                 536400
Declustered Array size (GiB):                             511334
Vdisk raw capacity  (GiB):                                 21300
Vdisk user data capacity (GiB):                            16890
Maximum file system size (set-size = 100%), (GiB):        405381
Maximum file system size (set-size = 100%), (TB):         435.27
  [16890 GiB per vdisk,  2 vdisks per node, 12 nodes]

Storage Efficiency:
--------------------
File system to total raw capacity:                        75.57%
File system to DA raw capacity:                           79.28%
8+2p erasure code efficiency:                             80.00%

Please be ready for 1% variations on all the calculations

```
