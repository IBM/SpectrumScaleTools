This tool will run a raw read storage test  using FIO tool and presenting the results on an easy to interpret manner. Also compares the device between them and against Key Performance Indicators (KPI)

NOTE: This test can require a long time to execute, depending on the number of devices. This tool will display an estimated runtime at startup.

Running on RHEL 8.x Systems Because RHEL8 does not define python executable, either version 2 or version 3 needs to be defined as default python. The way Redhat recommends to do so is using the alternatives command:

```
alternatives --config python
```

You must pick either python2 or python3. This tool will work with either python version.

An explanation of this can be found in many articles online, for example: https://developers.redhat.com/blog/2018/11/14/python-in-rhel-8/

PREREQUISITES: Before running this tool you must install the software prerequisites. Those are:

- The RPMs listed on the packages.json
- If running on Python 3 the python3-distro RPM
    
Remarks:

- This tool must be run with root privileges
- Guess drives only works on Python 3 environments
- The OS listed here are the supported for this tool. It does not imply on any way anything else beyond the scope of this tool
- The block sizes are RAW device block sizes, not related to Spectrum Scale nor Spectrum Scale RAID block sizes
- All drives must have at least a size of 8GB 
- The KPI are based on 128k block size. A run with 128 read test must be passed to certify the environment


TODO:
  - Add type of test as parameters

This tool comes with help with the ''-h'' or ''--help'' parameter
```
# ./nopeus.py -h

usage: nopeus.py [-h] [-b BS_CSV] [--guess-drives] [--i-want-to-lose-my-data]
                 [-t FIO_RUNTIME] [--rpm_check_disabled] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -b BS_CSV, --block-sizes BS_CSV
                        Block size for tests. The default and valid to certify
                        is 128k. The choices are: 4k 128k 256k 512k 1024k
  --guess-drives        It guesses the drives to test and adds them to the
                        drives.json file overwritting its content. You should
                        then manually review the file contect before running
                        the tool again
  --i-want-to-lose-my-data
                        It makes the test a write test instead of read. This
                        will delete the data that is on the drives. So if you
                        care about the keeping the data on the drives you
                        really should not run with this parameter. Running
                        with this paramenter will delete all data on the
                        drives
  -t FIO_RUNTIME, --time-per-test FIO_RUNTIME
                        The number of seconds to run each test. The value has
                        to be at least 30 seconds.The minimum required value
                        for certification is 300
  --rpm_check_disabled  Disables the RPM prerequisites check. Use only if you
                        are sure all required software is installed and no RPM
                        were used to install the required prerequisites.
                        Otherwise this tool will fail
  -v, --version         show program's version number and exit

```
To run this tool you need to either populate a drives.json with the devices you want to test or let the tool guess the drives and populate the drives.json file. You can later modify the self populated drive to adapt it to your needs.

To run with an already populated drives.json file:

```
# ./nopeus.py 

Welcome to NOPEUS, version 1.0

JSON files versions:
	supported OS:		1.0
	packages: 		1.0

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of NOPEUS is to obtain drive metrics, and compare them against KPIs

The FIO runtime per test of 300 seconds is sufficient to certify the environment

This test run estimation is 52 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload


We are going to test the following drives

	Drive: sdb as HDD
	Drive: sdc as HDD
	Drive: sdd as HDD
	Drive: sde as HDD
	Drive: sdf as HDD
	Drive: sdg as HDD
	Drive: sdh as HDD
	Drive: sdi as HDD
	Drive: sdj as HDD
	Drive: sdk as HDD

Do you want to continue? (y/n): 

```

If you want the tool to guess the drives (only on Python 3) and overwrite the content of drives.json:

```
# ./nopeus.py --guess-drives
OK: JSON file: drives.json [over]written

Welcome to NOPEUS, version 1.0

JSON files versions:
	supported OS:		1.0
	packages: 		1.o

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of NOPEUS is to obtain drive metrics, and compare them against KPIs

The FIO runtime per test of 300 seconds is sufficient to certify the environment

This test run estimation is 62 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload


We are going to test the following drives

	Drive: sdb as HDD
	Drive: sdc as HDD
	Drive: sdd as HDD
	Drive: sde as HDD
	Drive: sdf as HDD
	Drive: sdg as HDD
	Drive: sdh as HDD
	Drive: sdi as HDD
	Drive: sdj as HDD
	Drive: sdk as HDD
	Drive: nvme0n1 as NVME
	Drive: nvme1n1 as NVME

Do you want to continue? (y/n): 

```
A succesful run on a system with 2 NVMe devices would like the following:
```
# ./nopeus.py 

Welcome to NOPEUS, version 1.0

JSON files versions:
	supported OS:		1.0
	packages: 		1.0

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of NOPEUS is to obtain drive metrics, and compare them against KPIs

The FIO runtime per test of 300 seconds is sufficient to certify the environment

This test run estimation is 11 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload


We are going to test the following drives

	Drive: nvme0n1 as NVME
	Drive: nvme1n1 as NVME

Do you want to continue? (y/n):y 

INFO: checking packages install status
OK: installation status of fio is as expected
OK: the tool is being run as root
INFO: checking drives
INFO: nvme0n1 drive in the JSON file seems to be correctly populated
INFO: nvme1n1 drive in the JSON file seems to be correctly populated
INFO: checking devices status
OK: nvme0n1 defined by you as NVME is in the system as block device
OK: nvme1n1 defined by you as NVME is in the system as block device
INFO: Going to start test randread with blocksize of 128k on device nvme0n1 please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=2839MiB/s,w=0KiB/s][r=22.7k,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device nvme0n1
INFO: Going to start test randread with blocksize of 128k on device nvme1n1 please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=2845MiB/s,w=0KiB/s][r=22.8k,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device nvme1n1
INFO: All sinlge drive tests completed
OK: drive nvme0n1 with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with minimum IOPS of 22650.0 passes the HDD IOPS KPI of 10000.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with maximum latency of 3.13868 passes the NVME latency KPI of 10.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with mean IOPS of 22710.4 passes the NVME IOPS KPI of 15000.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with mean latency of 0.7 passes the NVME latency KPI of 1.0 for test nvme0n1_randread_128k
OK: drive nvme1n1 with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with minimum IOPS of 22650.0 passes the HDD IOPS KPI of 10000.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with maximum latency of 2.652423 passes the NVME latency KPI of 10.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with mean IOPS of 22716.68 passes the NVME IOPS KPI of 15000.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with mean latency of 0.7 passes the NVME latency KPI of 1.0 for test nvme1n1_randread_128k
INFO: drive type HDD was not tested, so no percentage difference applies for test nvme1n1_randread_128k
INFO: drive type SSD was not tested, so no percentage difference applies for test nvme1n1_randread_128k
OK: drive type NVME has IOPS percentage difference of 0.03 which passes the KPI of 10 for IOPS difference for same drive type for test nvme1n1_randread_128k
OK: drive type NVME has latency percentage difference of 0.0 which passes the KPI of 10 for latency difference for same drive type for test nvme1n1_randread_128k
OK: the difference between drives is acceptable by the KPIs

Summary of this run:
	SUCCESS: All drives fulfill the KPIs. You can continue with the next steps
```

A non succesful run (HDD and NVMe devices):
```
# ./nopeus.py 

Welcome to NOPEUS, version 1.0

JSON files versions:
	supported OS:		0.2
	packages: 		0.1

Please use https://github.com/IBM/SpectrumScaleTools to get latest versions and report issues about this tool.

The purpose of NOPEUS is to obtain drive metrics, and compare them against KPIs

The FIO runtime per test of 300 seconds is sufficient to certify the environment

This test run estimation is 62 minutes

This software comes with absolutely no warranty of any kind. Use it at your own risk

NOTE: The bandwidth numbers shown in this tool are for a very specific test. This is not a storage benchmark.
They do not necessarily reflect the numbers you would see with Spectrum Scale and your particular workload


We are going to test the following drives

	Drive: sdb as HDD
	Drive: sdc as HDD
	Drive: sdd as HDD
	Drive: sde as HDD
	Drive: sdf as HDD
	Drive: sdg as HDD
	Drive: sdh as HDD
	Drive: sdi as HDD
	Drive: sdj as HDD
	Drive: sdk as HDD
	Drive: nvme0n1 as NVME
	Drive: nvme1n1 as NVME

Do you want to continue? (y/n): y


INFO: checking packages install status
OK: installation status of fio is as expected
OK: the tool is being run as root
INFO: checking drives
INFO: sdb drive in the JSON file seems to be correctly populated
INFO: sdc drive in the JSON file seems to be correctly populated
INFO: sdd drive in the JSON file seems to be correctly populated
INFO: sde drive in the JSON file seems to be correctly populated
INFO: sdf drive in the JSON file seems to be correctly populated
INFO: sdg drive in the JSON file seems to be correctly populated
INFO: sdh drive in the JSON file seems to be correctly populated
INFO: sdi drive in the JSON file seems to be correctly populated
INFO: sdj drive in the JSON file seems to be correctly populated
INFO: sdk drive in the JSON file seems to be correctly populated
INFO: nvme0n1 drive in the JSON file seems to be correctly populated
INFO: nvme1n1 drive in the JSON file seems to be correctly populated
INFO: checking devices status
OK: sdb defined by you as HDD is in the system as block device
OK: sdc defined by you as HDD is in the system as block device
OK: sdd defined by you as HDD is in the system as block device
OK: sde defined by you as HDD is in the system as block device
OK: sdf defined by you as HDD is in the system as block device
OK: sdg defined by you as HDD is in the system as block device
OK: sdh defined by you as HDD is in the system as block device
OK: sdi defined by you as HDD is in the system as block device
OK: sdj defined by you as HDD is in the system as block device
OK: sdk defined by you as HDD is in the system as block device
OK: nvme0n1 defined by you as NVME is in the system as block device
OK: nvme1n1 defined by you as NVME is in the system as block device
INFO: Going to start test randread with blocksize of 128k on device sdb please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=18.3MiB/s,w=0KiB/s][r=146,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdb
INFO: Going to start test randread with blocksize of 128k on device sdc please be patient
Jobs: 1 (f=1): [r(1)][82.0%][r=6150KiB/s,w=0KiB/s][r=48,w=0 IOPS][eta 00m:09s] 
INFO: Completed test randread with blocksize of 128k on device sdc
INFO: Going to start test randread with blocksize of 128k on device sdd please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=17.8MiB/s,w=0KiB/s][r=142,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdd
INFO: Going to start test randread with blocksize of 128k on device sde please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=14.8MiB/s,w=0KiB/s][r=118,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sde
INFO: Going to start test randread with blocksize of 128k on device sdf please be patient
Jobs: 1 (f=0): [f(1)][100.0%][r=11.8MiB/s,w=0KiB/s][r=94,w=0 IOPS][eta 00m:00s] 
INFO: Completed test randread with blocksize of 128k on device sdf
INFO: Going to start test randread with blocksize of 128k on device sdg please be patient
Jobs: 1 (f=1): [r(1)][63.6%][r=0KiB/s,w=0KiB/s][r=0,w=0 IOPS][eta 00m:24s]     
INFO: Completed test randread with blocksize of 128k on device sdg
INFO: Going to start test randread with blocksize of 128k on device sdh please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=16.9MiB/s,w=0KiB/s][r=135,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdh
INFO: Going to start test randread with blocksize of 128k on device sdi please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=17.1MiB/s,w=0KiB/s][r=137,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdi
INFO: Going to start test randread with blocksize of 128k on device sdj please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=16.8MiB/s,w=0KiB/s][r=134,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdj
INFO: Going to start test randread with blocksize of 128k on device sdk please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=17.9MiB/s,w=0KiB/s][r=143,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device sdk
INFO: Going to start test randread with blocksize of 128k on device nvme0n1 please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=2838MiB/s,w=0KiB/s][r=22.7k,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device nvme0n1
INFO: Going to start test randread with blocksize of 128k on device nvme1n1 please be patient
Jobs: 1 (f=1): [r(1)][100.0%][r=2839MiB/s,w=0KiB/s][r=22.7k,w=0 IOPS][eta 00m:00s]
INFO: Completed test randread with blocksize of 128k on device nvme1n1
INFO: All sinlge drive tests completed
OK: drive sdb with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdb_randread_128k
OK: drive sdb with minimum IOPS of 98.0 passes the HDD IOPS KPI of 55.0 for test sdb_randread_128k
ERROR: drive sdb with maximum latency of 975.052538 does not pass the HDD latency KPI of 500.0 for test sdb_randread_128k
OK: drive sdb with mean IOPS of 139.07 passes the HDD IOPS KPI of 110.0 for test sdb_randread_128k
ERROR: drive sdb with mean latency of 115.62 does not pass the HDD latency KPI of 15.0 for test sdb_randread_128k
OK: drive sdc with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdc_randread_128k
ERROR: drive sdc with minimum IOPS of 2.0 does not pass the HDD IOPS KPI of 55.0 for test sdc_randread_128k
ERROR: drive sdc with maximum latency of 2294.778045 does not pass the HDD latency KPI of 500.0 for test sdc_randread_128k
ERROR: drive sdc with mean IOPS of 51.08 does not pass the HDD IOPS KPI of 110.0 for test sdc_randread_128k
ERROR: drive sdc with mean latency of 314.12 does not pass the HDD latency KPI of 15.0 for test sdc_randread_128k
OK: drive sdd with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdd_randread_128k
OK: drive sdd with minimum IOPS of 100.0 passes the HDD IOPS KPI of 55.0 for test sdd_randread_128k
ERROR: drive sdd with maximum latency of 890.515155 does not pass the HDD latency KPI of 500.0 for test sdd_randread_128k
OK: drive sdd with mean IOPS of 136.5 passes the HDD IOPS KPI of 110.0 for test sdd_randread_128k
ERROR: drive sdd with mean latency of 117.63 does not pass the HDD latency KPI of 15.0 for test sdd_randread_128k
OK: drive sde with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sde_randread_128k
OK: drive sde with minimum IOPS of 108.0 passes the HDD IOPS KPI of 55.0 for test sde_randread_128k
ERROR: drive sde with maximum latency of 1121.506619 does not pass the HDD latency KPI of 500.0 for test sde_randread_128k
OK: drive sde with mean IOPS of 134.83 passes the HDD IOPS KPI of 110.0 for test sde_randread_128k
ERROR: drive sde with mean latency of 118.96 does not pass the HDD latency KPI of 15.0 for test sde_randread_128k
OK: drive sdf with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdf_randread_128k
OK: drive sdf with minimum IOPS of 72.0 passes the HDD IOPS KPI of 55.0 for test sdf_randread_128k
ERROR: drive sdf with maximum latency of 1952.747656 does not pass the HDD latency KPI of 500.0 for test sdf_randread_128k
ERROR: drive sdf with mean IOPS of 101.23 does not pass the HDD IOPS KPI of 110.0 for test sdf_randread_128k
ERROR: drive sdf with mean latency of 159.94 does not pass the HDD latency KPI of 15.0 for test sdf_randread_128k
OK: drive sdg with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdg_randread_128k
ERROR: drive sdg with minimum IOPS of 2.0 does not pass the HDD IOPS KPI of 55.0 for test sdg_randread_128k
ERROR: drive sdg with maximum latency of 2409.470631 does not pass the HDD latency KPI of 500.0 for test sdg_randread_128k
ERROR: drive sdg with mean IOPS of 37.72 does not pass the HDD IOPS KPI of 110.0 for test sdg_randread_128k
ERROR: drive sdg with mean latency of 439.28 does not pass the HDD latency KPI of 15.0 for test sdg_randread_128k
OK: drive sdh with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdh_randread_128k
OK: drive sdh with minimum IOPS of 120.0 passes the HDD IOPS KPI of 55.0 for test sdh_randread_128k
ERROR: drive sdh with maximum latency of 1481.881603 does not pass the HDD latency KPI of 500.0 for test sdh_randread_128k
OK: drive sdh with mean IOPS of 141.62 passes the HDD IOPS KPI of 110.0 for test sdh_randread_128k
ERROR: drive sdh with mean latency of 113.76 does not pass the HDD latency KPI of 15.0 for test sdh_randread_128k
OK: drive sdi with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdi_randread_128k
OK: drive sdi with minimum IOPS of 120.0 passes the HDD IOPS KPI of 55.0 for test sdi_randread_128k
ERROR: drive sdi with maximum latency of 1104.732793 does not pass the HDD latency KPI of 500.0 for test sdi_randread_128k
OK: drive sdi with mean IOPS of 139.17 passes the HDD IOPS KPI of 110.0 for test sdi_randread_128k
ERROR: drive sdi with mean latency of 115.43 does not pass the HDD latency KPI of 15.0 for test sdi_randread_128k
OK: drive sdj with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdj_randread_128k
OK: drive sdj with minimum IOPS of 124.0 passes the HDD IOPS KPI of 55.0 for test sdj_randread_128k
ERROR: drive sdj with maximum latency of 958.411167 does not pass the HDD latency KPI of 500.0 for test sdj_randread_128k
OK: drive sdj with mean IOPS of 142.88 passes the HDD IOPS KPI of 110.0 for test sdj_randread_128k
ERROR: drive sdj with mean latency of 112.39 does not pass the HDD latency KPI of 15.0 for test sdj_randread_128k
OK: drive sdk with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test sdk_randread_128k
OK: drive sdk with minimum IOPS of 102.0 passes the HDD IOPS KPI of 55.0 for test sdk_randread_128k
ERROR: drive sdk with maximum latency of 1139.463901 does not pass the HDD latency KPI of 500.0 for test sdk_randread_128k
OK: drive sdk with mean IOPS of 137.13 passes the HDD IOPS KPI of 110.0 for test sdk_randread_128k
ERROR: drive sdk with mean latency of 116.96 does not pass the HDD latency KPI of 15.0 for test sdk_randread_128k
OK: drive nvme0n1 with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with minimum IOPS of 22668.0 passes the HDD IOPS KPI of 10000.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with maximum latency of 2.01171 passes the NVME latency KPI of 10.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with mean IOPS of 22712.8 passes the NVME IOPS KPI of 15000.0 for test nvme0n1_randread_128k
OK: drive nvme0n1 with mean latency of 0.7 passes the NVME latency KPI of 1.0 for test nvme0n1_randread_128k
OK: drive nvme1n1 with IO drop[s] of 0.0 passes the IO drops KPI of 0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with minimum IOPS of 22650.0 passes the HDD IOPS KPI of 10000.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with maximum latency of 2.3625 passes the NVME latency KPI of 10.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with mean IOPS of 22712.9 passes the NVME IOPS KPI of 15000.0 for test nvme1n1_randread_128k
OK: drive nvme1n1 with mean latency of 0.7 passes the NVME latency KPI of 1.0 for test nvme1n1_randread_128k
ERROR: drive type HDD has IOPS percentage difference of 73.6 which does not pass the KPI of 10 for IOPS difference for same drive type for test nvme1n1_randread_128k
ERROR: drive type HDD has latency percentage difference of 74.41 which does not pass the KPI of 10 for latency difference for same drive type for test nvme1n1_randread_128k
INFO: drive type SSD was not tested, so no percentage difference applies for test nvme1n1_randread_128k
OK: drive type NVME has IOPS percentage difference of 0.0 which passes the KPI of 10 for IOPS difference for same drive type for test nvme1n1_randread_128k
OK: drive type NVME has latency percentage difference of 0.0 which passes the KPI of 10 for latency difference for same drive type for test nvme1n1_randread_128k
ERROR: the difference between drives is not acceptable by the KPIs

Summary of this run:
	FAILURE: All drives do not fulfill the KPIs. You *cannot* continue with the next steps
	ERROR: The settings of this test run do not qualify as a valid run to check their KPIs. You *cannot* continue with the next steps
```
