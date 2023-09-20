This tool uses FIO benchmark to run test agianst raw storage devices and presents the results in a way that is easy to interpret. compares the test results with Key Performance Indicators (KPI) and determines if storage devices in localhost were ready to run IBM Storage Scale Erasure Code Edition.

NOTE: A test instance started by this tool may require a long time, depending on the number of storage devices. This tool will display an estimated time consumption at startup. It is recommended to run instance under session of screen or tmux.

Remarks:

- This tool must be run with root privileges
- Guess drives works if lsblk command supported '--json' option
- The block size in this tool is for each I/O operation, not related to IBM Storage Scale nor IBM Storage Scale RAID block size
- The KPIs are based on 128k block size. The 128k random read test must be passed to certify the environment

KPIs for certification.
```
NVMe drive:
    drop I/Os:   0
    IOPS:
        minimum: 10000
        mean:    15000
    latency:
        maximum: 20 msec
        mean:    1.5 msec
SSD:
    drop I/Os:   0
    IOPS:
        minimum: 800
        mean:    1200
    latency:
        maximum: 100 msec
        mean:    20.0 msec
HDD:
    drop I/Os:   0
    IOPS:
        minimum: 55
        mean:    110
    latency:
        maximum: 1500 msec
        mean:    150.0 msec
max diff rate:   10%
```
Above KPIs has been saved in file randread_128KiB_16iodepth_KPIs.json

Usage of this tool.
```
# python3 nopeus.py -h
usage: nopeus.py [-h] [-g] [-b {4k,128k,256k,512k,1m,2m}] [-j JOBNUM]
                 [-t RUNTIME] [-w] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -g, --guess-devices   guess the storage devices then overwrite them to
                        storage_devices.json. It is recommended to review
                        storage_devices.json before starting storage readiness
                        testing
  -b {4k,128k,256k,512k,1m,2m}, --block-size {4k,128k,256k,512k,1m,2m}
                        block size in bytes used for fio I/O units. The
                        default I/O block size is 128k which is also for
                        certification
  -j JOBNUM, --job-per-device JOBNUM
                        fio job number for each deivce. For certification, it
                        must be 1. This tool implies the 16 I/O queue depth
                        for each fio instance
  -t RUNTIME, --runtime-per-instance RUNTIME
                        runtime in second for each fio instance. It should be
                        at least 30 sec even if ran quick testing. For
                        certification, it must be at least 300 sec
  -w, --random-write    use randwrite option to start fio instance instead of
                        randread. This would corrupt data that stored in the
                        storage devices. Ensure the original data on storage
                        devices has been backed up or could be corrupted
                        before specified this option
  -v, --version         show program's version number and exit
```

Populate the storage_devices.json file with storage devices to be test or let the tool guess the storage drives and populate the storage_devices.json file before starting readiness test. It is recommended to review the file carefully before any testing.

An example with default option and storage_devices.json has been populated
```
# python3 nopeus.py

Welcome to Storage Readiness 1.21

The purpose of this tool is to obtain storage device metrics of localhost then compare them against certain KPIs
Please access https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

NOTE:
  This software absolutely comes with no warranty of any kind. Use it at your own risk.
  The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] Current user is root
[ INFO  ] fio benchmark is available with version fio-3.30

[ INFO  ] Extract storage device from storage_devices.json

[ INFO  ] Extract testable storage device list
[ INFO  ] /dev/sdd is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sde is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdf is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdg is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/nvme1n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme0n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme2n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme3n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] Above storage device list is OK to be tested

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0

[ INFO  ] To certify the storage device:
[ INFO  ] fio needs at least 300 sec runtime per instance. Current setting is 300 sec
[ INFO  ] fio needs 128k blocksize for each I/O unit. Current setting is 128k
[ INFO  ] fio needs 1 job for each storage device. Current setting is 1
[ INFO  ] fio needs 'randread' I/O type. Current setting is 'randread'

[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~52 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>:
```

An example with '--guess-devices' option to populated storage_devices.json
```
# python3 nopeus.py --guess-devices

Welcome to Storage Readiness 1.21

The purpose of this tool is to obtain storage device metrics of localhost then compare them against certain KPIs
Please access https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

NOTE:
  This software absolutely comes with no warranty of any kind. Use it at your own risk.
  The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] Current user is root
[ INFO  ] fio benchmark is available with version fio-3.30

[ INFO  ] Guess localhost OS boot device
[ INFO  ] Guess testable storage device of localhost

[ INFO  ] Extract testable storage device list
[ INFO  ] /dev/sdd is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sde is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdf is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdg is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/nvme1n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme0n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme2n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme3n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] Above storage device list is OK to be tested

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0

[ INFO  ] To certify the storage device:
[ INFO  ] fio needs at least 300 sec runtime per instance. Current setting is 300 sec
[ INFO  ] fio needs 128k blocksize for each I/O unit. Current setting is 128k
[ INFO  ] fio needs 1 job for each storage device. Current setting is 1
[ INFO  ] fio needs 'randread' I/O type. Current setting is 'randread'

[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~347 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>:
```

An example with customized option that is not suitable to run storage readiness test
```
# python3 nopeus.py -b 1m -j 4 -t 120 -w

Welcome to Storage Readiness 1.21

The purpose of this tool is to obtain storage device metrics of localhost then compare them against certain KPIs
Please access https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

NOTE:
  This software absolutely comes with no warranty of any kind. Use it at your own risk.
  The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] Current user is root
[ INFO  ] fio benchmark is available with version fio-3.30

[ INFO  ] Extract storage device from storage_devices.json

[ INFO  ] Extract testable storage device list
[ INFO  ] /dev/sdd is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sde is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdf is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdg is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/nvme1n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme0n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme2n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme3n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] Above storage device list is OK to be tested

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0

[ INFO  ] To certify the storage device:
[ WARN  ] fio needs at least 300 sec runtime per instance. Current setting is 120 sec
[ WARN  ] fio needs 128k blocksize for each I/O unit. Current setting is 1m
[ WARN  ] fio needs 1 job for each storage device. Current setting is 4
[ WARN  ] fio needs 'randread' I/O type. Current setting is 'randwrite'
[ FATAL ] Input argument is not suitable for storage readiness. However, it can do ordinary performance test
[ FATAL ] This instance will show the performance test result, but will not compare it with any KPI

[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~22 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue, 'no' to stop
Continue? <yes|no>: yes


Random write I/O type was enabled. It will corrupt data in above storage device list
In above storage device list, double check that Operation System is NOT installed
In above storage device list, double check that user data has been backed up

Type 'I CONFIRM' to allow data on storage devices to be corrupted. Otherwise, exit
Confirm? \<I CONFIRM>: I CONFIRM

Type 'I CONFIRM' again to ensure you allow data to be corrupted. Otherwise, exit
Confirm? \<I CONFIRM>: no
[ QUIT  ] Leave the data as it is. Bye!
```

Output of a successful example with default option
```
# python3 nopeus.py

Welcome to Storage Readiness 1.21

The purpose of this tool is to obtain storage device metrics of localhost then compare them against certain KPIs
Please access https://github.com/IBM/SpectrumScaleTools to get required version and report issue if necessary

NOTE:
  This software absolutely comes with no warranty of any kind. Use it at your own risk.
  The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
  The numbers do not reflect any specification of IBM Storage Scale or any user workload running on it.

[ INFO  ] Current user is root
[ INFO  ] fio benchmark is available with version fio-3.30

[ INFO  ] Extract storage device from storage_devices.json

[ INFO  ] Extract testable storage device list
[ INFO  ] /dev/sdd is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sde is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdf is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/sdg is HDD and a block device. Its size is 14.6T
[ INFO  ] /dev/nvme1n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme0n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme2n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] /dev/nvme3n1 is NVME and a block device. Its size is 2.9T
[ INFO  ] Above storage device list is OK to be tested

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0

[ INFO  ] To certify the storage device:
[ INFO  ] fio needs at least 300 sec runtime per instance. Current setting is 300 sec
[ INFO  ] fio needs 128k blocksize for each I/O unit. Current setting is 128k
[ INFO  ] fio needs 1 job for each storage device. Current setting is 1
[ INFO  ] fio needs 'randread' I/O type. Current setting is 'randread'

[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~52 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>: yes

[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdd, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdd, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sde, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sde, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdf, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdf, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdg, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdg, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme1n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme1n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme0n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme0n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme2n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme2n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme3n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme3n1, has completed
[ INFO  ] Single storage device tests completed

[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 4 job(s), against all HDD devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all HDD devices, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 4 job(s), against all NVME devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all NVME devices, has completed
[ INFO  ] Multiple storage device tests completed

[ INFO  ] Check if performance numbers of single storage device meet the required KPIs

[ INFO  ] /dev/sdd has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sdd has 140.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sdd has 160.23 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sdd has 528.95 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sdd has 99.85 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sde has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sde has 96.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sde has 158.08 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sde has 575.12 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sde has 101.21 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sdf has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sdf has 134.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sdf has 160.16 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sdf has 549.65 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sdf has 99.9 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sdg has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sdg has 124.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sdg has 159.75 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sdg has 565.68 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sdg has 100.15 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/nvme1n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme1n1 has 22760.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme1n1 has 22775.07 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme1n1 has 2.73 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme1n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme0n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme0n1 has 22759.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 22775.3 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 2.52 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme0n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme2n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme2n1 has 22759.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme2n1 has 22775.35 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme2n1 has 2.41 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme2n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme3n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme3n1 has 22759.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme3n1 has 22775.23 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme3n1 has 3.12 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme3n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Check if performance numbers of multiple storage devices meet the required KPIs

[ INFO  ] HDD has 0 drop I/O(s) which meets the required 0 drop I/O KPI of HDD
[ INFO  ] HDD has 123.0 average minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] HDD has 159.61 average mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] HDD has 683.53 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] HDD has 100.3 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] NVME has 0 drop I/O(s) which meets the required 0 drop I/O KPI of NVME
[ INFO  ] NVME has 22694.75 average minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] NVME has 22757.0 average mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] NVME has 3.46 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] NVME has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Define difference percentage as 100 * (max - min) / max
[ INFO  ] Check if difference percentage of IOPS and latency meets the KPI

[ INFO  ] All HDDs have 1.34% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All HDDs have 1.34% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All NVMEs have 0.0% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All NVMEs have 0.0% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All types of storage devices passed the KPI check

[ INFO  ] Storage device of this host is ready to run the next procedure
```
