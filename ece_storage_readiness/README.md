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

The output should look like the following if run with an already populated drives.json file.
```
# python3 nopeus.py

Welcome to storage readiness tool, version 1.20

Please access https://github.com/IBM/SpectrumScaleTools to get the latest version or report issue(s)

The purpose of this tool is to obtain drive metrics, then compare them against certain KPIs

NOTE: This software absolutely comes with no warranty of any kind. Use it at your own risk.
      The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
      The numbers do not reflect any specification of IBM Storage Scale or any performance number of user's workload.

[ INFO  ] Current user is root
[ INFO  ] Extract storage device(s) from storage_devices.json

[ INFO  ] Got below storage devices to be tested
[ INFO  ] HDD /dev/sdd is a block device
[ INFO  ] HDD /dev/sde is a block device
[ INFO  ] HDD /dev/sdf is a block device
[ INFO  ] HDD /dev/sdg is a block device
[ INFO  ] NVME /dev/nvme0n1 is a block device
[ INFO  ] NVME /dev/nvme1n1 is a block device
[ INFO  ] NVME /dev/nvme2n1 is a block device
[ INFO  ] NVME /dev/nvme3n1 is a block device
[ INFO  ] Above storage devices are all block devices

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0
[ INFO  ] The 300 sec runtime per fio instance is sufficient to do storage certification
[ INFO  ] The 128KiB blocksize for each I/O unit is valid to do storage certification
[ INFO  ] The 1 fio job number for each storage device is valid to do storage certification
[ INFO  ] The randread I/O type is valid to do storage certification
[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~52 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>:

```

The output should look like the following if guess the drives and overwrite the content of drives.json
```
# python3 nopeus.py --guess-devices

Welcome to storage readiness tool, version 1.20

Please access https://github.com/IBM/SpectrumScaleTools to get the latest version or report issue(s)

The purpose of this tool is to obtain drive metrics, then compare them against certain KPIs

NOTE: This software absolutely comes with no warranty of any kind. Use it at your own risk.
      The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
      The numbers do not reflect any specification of IBM Storage Scale or any performance number of user's workload.

[ INFO  ] Current user is root
[ INFO  ] Guess localhost OS boot device
[ INFO  ] Guess storage devices in localhost

[ INFO  ] Got below storage devices to be tested
[ INFO  ] HDD /dev/sdd is a block device
[ INFO  ] HDD /dev/sde is a block device
[ INFO  ] HDD /dev/sdf is a block device
[ INFO  ] HDD /dev/sdg is a block device
[ INFO  ] NVME /dev/nvme0n1 is a block device
[ INFO  ] NVME /dev/nvme2n1 is a block device
[ INFO  ] NVME /dev/nvme1n1 is a block device
[ INFO  ] NVME /dev/nvme3n1 is a block device
[ INFO  ] Above storage devices are all block devices

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0
[ INFO  ] The 300 sec runtime per fio instance is sufficient to do storage certification
[ INFO  ] The 128KiB blocksize for each I/O unit is valid to do storage certification
[ INFO  ] The 1 fio job number for each storage device is valid to do storage certification
[ INFO  ] The randread I/O type is valid to do storage certification
[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~52 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>: 

```

The output should look like the following if run random write test which would corrupt data.
```
# python3 nopeus.py -b 1m -j 4 -t 360 -w

Welcome to storage readiness tool, version 1.20

Please access https://github.com/IBM/SpectrumScaleTools to get the latest version or report issue(s)

The purpose of this tool is to obtain drive metrics, then compare them against certain KPIs

NOTE: This software absolutely comes with no warranty of any kind. Use it at your own risk.
      The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
      The numbers do not reflect any specification of IBM Storage Scale or any performance number of user's workload.

[ INFO  ] Current user is root
[ INFO  ] Extract storage device(s) from storage_devices.json

[ INFO  ] Got below storage devices to be tested
[ INFO  ] NVME /dev/nvme1n1 is a block device
[ INFO  ] NVME /dev/nvme0n1 is a block device
[ INFO  ] HDD /dev/sdbe is a block device
[ INFO  ] HDD /dev/sdbd is a block device
[ INFO  ] HDD /dev/sdbg is a block device
[ INFO  ] HDD /dev/sdbf is a block device
[ INFO  ] Above storage devices are all block devices

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0
[ INFO  ] The 360 sec runtime per fio instance is sufficient to do storage certification
[ WARN  ] The 1m blocksize for each I/O unit is invalid to certify storage devices
[ WARN  ] The 4 fio job number for storage device(s) is invalid to certify storage devices
[ WARN  ] The randwrite I/O type is invalid to certify storage devices
[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~50 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>: yes


[ WARN  ] Random write I/O type was enabled. It will corrupt data on storage devices
[ WARN  ] For above devices, double check if Operation System was NOT installed on
[ WARN  ] For above devices, double check if user data has been backed up

Type 'I CONFIRM' to allow data on storage devices to be corrupted. Otherwise, exit
Confirm? <I CONFIRM>: I CONFIRM

Type 'I CONFIRM' again to ensure you allow data to be corrupted. Otherwise, exit
Confirm? <I CONFIRM>: I CONFIRM

```

A succesful instance on a system with 2 NVMe drives should look as follows:
```
# python3 nopeus.py

Welcome to storage readiness tool, version 1.20

Please access https://github.com/IBM/SpectrumScaleTools to get the latest version or report issue(s)

The purpose of this tool is to obtain drive metrics, then compare them against certain KPIs

NOTE: This software absolutely comes with no warranty of any kind. Use it at your own risk.
      The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
      The numbers do not reflect any specification of IBM Storage Scale or any performance number of user's workload.

[ INFO  ] Current user is root
[ INFO  ] Extract storage device(s) from storage_devices.json

[ INFO  ] Got below storage devices to be tested
[ INFO  ] NVME /dev/nvme0n1 is a block device
[ INFO  ] NVME /dev/nvme1n1 is a block device
[ INFO  ] Above storage devices are all block devices

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0
[ INFO  ] The 300 sec runtime per fio instance is sufficient to do storage certification
[ INFO  ] The 128KiB blocksize for each I/O unit is valid to do storage certification
[ INFO  ] The 1 fio job number for each storage device is valid to do storage certification
[ INFO  ] The randread I/O type is valid to do storage certification
[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~16 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>: yes

[ INFO  ] This host has fio binary file with version fio-3.30 which could be used directly
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme0n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme0n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme1n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme1n1, has completed
[ INFO  ] Single storage device tests completed

[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 2 job(s), against all NVME devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all NVME devices, has completed
[ INFO  ] Multiple storage device tests completed

[ INFO  ] Check if performance numbers of single storage device meet the required KPIs

[ INFO  ] /dev/nvme0n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme0n1 has 22720.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 22772.86 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 2.89 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme0n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme1n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme1n1 has 22752.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme1n1 has 22772.75 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme1n1 has 2.45 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme1n1 has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Check if performance numbers of multiple storage devices meet the required KPIs

[ INFO  ] NVME has 0 drop I/O(s) which meets the required 0 drop I/O KPI of NVME
[ INFO  ] NVME has 22534.0 average minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] NVME has 22746.39 average mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] NVME has 9.27 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] NVME has 0.7 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Define difference percentage as 100 * (max - min) / max
[ INFO  ] Check if difference percentage of IOPS and latency meets the KPI

[ INFO  ] HDD device number is not enough to do difference percentage checking

[ INFO  ] SSD device number is not enough to do difference percentage checking

[ INFO  ] All NVMEs have 0.0% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All NVMEs have 0.0% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All types of storage devices passed the KPI check

[ INFO  ] All storage devices are ready to run the next procedure

```

An unsuccesful instance on a system with 3 HDDs 3 SSDs and 3 NVMe drives should look as follows:
```
# python3 nopeus.py

Welcome to storage readiness tool, version 1.20

Please access https://github.com/IBM/SpectrumScaleTools to get the latest version or report issue(s)

The purpose of this tool is to obtain drive metrics, then compare them against certain KPIs

NOTE: This software absolutely comes with no warranty of any kind. Use it at your own risk.
      The IOPS and latency numbers shown are under special parameters. That is not a generic storage standard.
      The numbers do not reflect any specification of IBM Storage Scale or any performance number of user's workload.

[ INFO  ] Current user is root
[ INFO  ] Extract storage device(s) from storage_devices.json

[ INFO  ] Got below storage devices to be tested
[ INFO  ] HDD /dev/sda is a block device
[ INFO  ] HDD /dev/sdb is a block device
[ INFO  ] HDD /dev/sdg is a block device
[ INFO  ] SSD /dev/sdc is a block device
[ INFO  ] SSD /dev/sdd is a block device
[ INFO  ] SSD /dev/sde is a block device
[ INFO  ] NVME /dev/nvme2n1 is a block device
[ INFO  ] NVME /dev/nvme1n1 is a block device
[ INFO  ] NVME /dev/nvme0n1 is a block device
[ INFO  ] Above storage devices are all block devices

[ INFO  ] Extracted KPIs from randread_128KiB_16iodepth_KPIs.json with version 1.0
[ INFO  ] The 300 sec runtime per fio instance is sufficient to do storage certification
[ INFO  ] The 128KiB blocksize for each I/O unit is valid to do storage certification
[ INFO  ] The 1 fio job number for each storage device is valid to do storage certification
[ INFO  ] The randread I/O type is valid to do storage certification
[ INFO  ] The total time consumption of running this storage readiness instance is estimated to take ~62 minutes
[ INFO  ] Please check above messages, especially the storage devices to be tested
Type 'yes' to continue testing, 'no' to stop
Continue? <yes|no>: yes

[ INFO  ] This host has fio binary file with version fio-3.7 which could be used directly
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sda, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sda, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdb, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdb, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdg, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdg, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdc, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdc, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sdd, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sdd, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against sde, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against sde, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme2n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme2n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme1n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme1n1, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 1 job(s), against nvme0n1, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against nvme0n1, has completed
[ INFO  ] Single storage device tests completed

[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 3 job(s), against all HDD devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all HDD devices, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 3 job(s), against all SSD devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all SSD devices, has completed
[ INFO  ] Start fio instance with randread I/O type, 128k I/O blocksize, 3 job(s), against all NVME devices, runtime 300 sec, ramp time 10 sec
[ INFO  ] Please wait for the instance to complete
[ INFO  ] randread fio instance with 128k I/O blocksize, against all NVME devices, has completed
[ INFO  ] Multiple storage device tests completed

[ INFO  ] Check if performance numbers of single storage device meet the required KPIs

[ INFO  ] /dev/sda has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sda has 166.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sda has 213.42 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sda has 1115.24 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sda has 74.95 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sdb has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sdb has 172.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sdb has 209.59 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sdb has 1189.04 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sdb has 76.32 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sdg has 0 drop I/O which meets the required 0 drop I/O KPI of HDD
[ INFO  ] /dev/sdg has 178.0 minimum IOPS which meets the required 55.0 minimum IOPS KPI of HDD
[ INFO  ] /dev/sdg has 226.33 mean IOPS which meets the required 110.0 mean IOPS KPI of HDD
[ INFO  ] /dev/sdg has 969.91 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] /dev/sdg has 70.67 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] /dev/sdc has 0 drop I/O which meets the required 0 drop I/O KPI of SSD
[ INFO  ] /dev/sdc has 3176.0 minimum IOPS which meets the required 800.0 minimum IOPS KPI of SSD
[ INFO  ] /dev/sdc has 3310.58 mean IOPS which meets the required 1200.0 mean IOPS KPI of SSD
[ INFO  ] /dev/sdc has 19.88 msec maximum latency which meets the required 100.0 msec maximum latency KPI of SSD
[ INFO  ] /dev/sdc has 4.81 msec mean latency which meets the required 20.0 msec mean latency KPI of SSD

[ INFO  ] /dev/sdd has 0 drop I/O which meets the required 0 drop I/O KPI of SSD
[ INFO  ] /dev/sdd has 3224.0 minimum IOPS which meets the required 800.0 minimum IOPS KPI of SSD
[ INFO  ] /dev/sdd has 3291.44 mean IOPS which meets the required 1200.0 mean IOPS KPI of SSD
[ INFO  ] /dev/sdd has 13.21 msec maximum latency which meets the required 100.0 msec maximum latency KPI of SSD
[ INFO  ] /dev/sdd has 4.83 msec mean latency which meets the required 20.0 msec mean latency KPI of SSD

[ INFO  ] /dev/sde has 0 drop I/O which meets the required 0 drop I/O KPI of SSD
[ INFO  ] /dev/sde has 3140.0 minimum IOPS which meets the required 800.0 minimum IOPS KPI of SSD
[ INFO  ] /dev/sde has 3249.38 mean IOPS which meets the required 1200.0 mean IOPS KPI of SSD
[ INFO  ] /dev/sde has 14.85 msec maximum latency which meets the required 100.0 msec maximum latency KPI of SSD
[ INFO  ] /dev/sde has 4.9 msec mean latency which meets the required 20.0 msec mean latency KPI of SSD

[ INFO  ] /dev/nvme2n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme2n1 has 16922.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme2n1 has 17060.42 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme2n1 has 2.32 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme2n1 has 0.92 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme1n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme1n1 has 15596.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme1n1 has 17102.53 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ FATAL ] /dev/nvme1n1 has 45.06 msec maximum latency which is over the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme1n1 has 0.92 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] /dev/nvme0n1 has 0 drop I/O which meets the required 0 drop I/O KPI of NVME
[ INFO  ] /dev/nvme0n1 has 16956.0 minimum IOPS which meets the required 10000.0 minimum IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 17116.87 mean IOPS which meets the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] /dev/nvme0n1 has 3.97 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] /dev/nvme0n1 has 0.92 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Check if performance numbers of multiple storage devices meet the required KPIs

[ INFO  ] HDD has 0 drop I/O(s) which meets the required 0 drop I/O KPI of HDD
[ FATAL ] HDD has 50.67 average minimum IOPS which is below the required 55.0 minimum IOPS KPI of HDD
[ FATAL ] HDD has 73.46 average mean IOPS which is below the required 110.0 mean IOPS KPI of HDD
[ INFO  ] HDD has 1199.22 msec maximum latency which meets the required 1500.0 msec maximum latency KPI of HDD
[ INFO  ] HDD has 72.58 msec mean latency which meets the required 150.0 msec mean latency KPI of HDD

[ INFO  ] SSD has 0 drop I/O(s) which meets the required 0 drop I/O KPI of SSD
[ INFO  ] SSD has 1067.33 average minimum IOPS which meets the required 800.0 minimum IOPS KPI of SSD
[ FATAL ] SSD has 1088.72 average mean IOPS which is below the required 1200.0 mean IOPS KPI of SSD
[ INFO  ] SSD has 17.78 msec maximum latency which meets the required 100.0 msec maximum latency KPI of SSD
[ INFO  ] SSD has 4.87 msec mean latency which meets the required 20.0 msec mean latency KPI of SSD

[ INFO  ] NVME has 0 drop I/O(s) which meets the required 0 drop I/O KPI of NVME
[ FATAL ] NVME has 5648.0 average minimum IOPS which is below the required 10000.0 minimum IOPS KPI of NVME
[ FATAL ] NVME has 5704.14 average mean IOPS which is below the required 15000.0 mean IOPS KPI of NVME
[ INFO  ] NVME has 4.27 msec maximum latency which meets the required 20.0 msec maximum latency KPI of NVME
[ INFO  ] NVME has 0.91 msec mean latency which meets the required 1.5 msec mean latency KPI of NVME

[ INFO  ] Define difference percentage as 100 * (max - min) / max
[ INFO  ] Check if difference percentage of IOPS and latency meets the KPI

[ INFO  ] All HDDs have 7.4% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All HDDs have 7.4% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All SSDs have 1.85% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All SSDs have 1.84% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All NVMEs have 0.33% difference of IOPS which meets required 10% maximum difference percentage KPI
[ INFO  ] All NVMEs have 0.0% difference of latency which meets required 10% maximum difference percentage KPI

[ INFO  ] All types of storage devices passed the KPI check

[ FATAL ] *NOT* all storage devices are ready. Storage devices in this host *CANNOT* be used by IBM Storage Scale
```
