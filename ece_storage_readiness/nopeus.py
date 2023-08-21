"""
This module can launch random read test against raw storage device
using FIO benchmark and present the results in a way that is easy to interpret.
It compares the test results with Key Performance Indicators (KPI) then
determines if the storage devices in localhost is ready.
"""

import json
import os
import sys
import datetime
import argparse
import shlex
from math import ceil
from stat import S_ISBLK
from subprocess import Popen, PIPE

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[92m'
PURPLE = '\033[35m'
YELLOW = '\033[93m'
RESETCOLOR = '\033[0m'

INFO = "[ {0}INFO{1}  ] ".format(GREEN, RESETCOLOR)
WARN = "[ {0}WARN{1}  ] ".format(YELLOW, RESETCOLOR)
ERRO = "[ {0}FATAL{1} ] ".format(RED, RESETCOLOR)
QUIT = "[ {0}QUIT{1}  ] ".format(RED, RESETCOLOR)

VERSION = "1.20"
GIT_URL = "https://github.com/IBM/SpectrumScaleTools"
BASEDIR = os.path.dirname(os.path.realpath(__file__))

"""
Default options for this script command line
"""
DEFAULT_BS = '128k'
DEFAULT_NJ = 1
DEFAULT_RT = 300
BS_CHOICES = ['4k', '128k', '256k', '512k', '1m', '2m']
STORDEV_FL = "{}/storage_devices.json".format(BASEDIR)

try:
    input = raw_input
except NameError:
    pass


def load_json(json_file):
    """
    Params:
        json_file: a file path string with json format.
    Returns:
        Python Dictionary object load from json file.
        None if hit error.
    """
    if not json_file or isinstance(json_file, str) is False:
        print("{}Invalid parameter: json_file".format(ERRO))
        return None
    try:
        with open(json_file, 'r') as fh:
            return json.load(fh)
    except Exception as e:
        print("{0}Tried to load JSON file {1} but hit ".format(ERRO, json_file) +
              "exception: {}".format(e))
        return None


def dump_json(src_kv, dst_file):
    """
    Params:
        src_kv: Python dictionay object to be recorded.
        dst_file: a file path used to save Python dictionay object.
    Returns:
        0 if succeeded.
        1 if hit error.
    """
    if not src_kv or isinstance(src_kv, dict) is False:
        print("{}Invalid parameter: src_kv".format(ERRO))
        return 1
    if not dst_file or isinstance(dst_file, str) is False:
        print("{}Invalid parameter: dst_file".format(ERRO))
        return 1

    try:
        src_data = json.dumps(src_kv, indent=4)
        with open(dst_file, 'w') as fh:
            fh.write(src_data)
        return 0
    except Exception as e:
        print("{0}Tried to [over]write {1} but hit exception: {2}\n".format(
              ERRO, dst_file, e))
        return 1


def is_fio_available():
    """
    Params:
    Returns:
        0 if fio is available.
        1 if not.
    """
    child = Popen(shlex.split('fio -v'), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = child.communicate()
    out = out.strip()
    if child.returncode != 0 or not out:
        print("{}Ran cmd: fio -v".format(INFO))
        if err:
            if isinstance(err, bytes) is True:
                err = err.decode()
            print("{0}{1}".format(ERRO, err))
        print("{}It seems fio is not available on this host".format(ERRO))
        return 1
    if isinstance(out, bytes) is True:
        out = out.decode()
    fio_ver = out.strip()
    print("{0}This host has fio binary file with version {1} ".format(INFO,
          fio_ver) + "which could be used directly")
    return 0


def check_root_user():
    """
    Params:
    Returns:
        0 if under root user.
        1 if not under root user or hit error.
    """
    try:
        effective_uid = os.getuid()
    except BaseException as e:
        print("{}Tried to get current UID but hit ".format(ERRO) +
              "exception: {}\n".format(e))
        return 1

    if effective_uid == 0:
        print("{}Current user is root".format(INFO))
        return 0
    else:
        print("{}This tool should be run under root user".format(ERRO))
        return 1


def is_file_readable(fp):
    """
    Params:
        fp: a file path string.
    Returns:
        'yes' if given file is readable.
        'no' if hit error.
    """
    if not fp or isinstance(fp, str) is False:
        print("{}Invalid parameter: fp".format(ERRO))
        return 'no'
    if os.path.isfile(fp) is False:
        print("{0}{1} is not a rugular file".format(ERRO, fp))
        return 'no'
    if os.access(fp, os.R_OK) is False:
        print("{0}{1} does not have read permission".format(ERRO, fp))
        return 'no'
    if os.path.getsize(fp) == 0:
        print("{0}{1} is an empy file".format(ERRO, fp))
        return 'no'
    return 'yes'


def get_boot_devices():
    """
    Params:
    Returns:
        ['/dev/sdx', '/dev/sdy',...] if succeeded.
        [] if no boot device.
        ['error'] if hit error.
    """
    print("{}Guess localhost OS boot device".format(INFO))
    child = Popen(shlex.split('df -l'), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = child.communicate()
    out = out.strip()
    if child.returncode != 0 or not out:
        print("{}Ran cmd: df -l".format(INFO))
        if err:
            if isinstance(err, bytes) is True:
                err = err.decode()
            print("{0}{1}".format(ERRO, err))
        print("{}Failed to get localhost boot device".format(ERRO))
        return ['error']
    if isinstance(out, bytes) is True:
        out = out.decode()
    boot_devs = []
    out_lines = out.splitlines()
    for line in out_lines:
        if '/boot' in line and '/boot/' not in line:
            line_to_list = line.split()
            boot_dev = ''.join([c for c in line_to_list[0] if not c.isdigit()])
            boot_devs.append(boot_dev)
    if not boot_devs:
        print("{}It seems localhost has no boot device".format(WARN))
    return boot_devs


def guess_storage_devices():
    """
    Params:
    Returns:
        {'/dev/sda': 'HDD', ...} if succeeded.
        {} if hit error.
    """
    boot_devs = get_boot_devices()
    if 'error' in boot_devs:
        return {}
    print("{}Guess storage devices in localhost".format(INFO))
    lsblk_cmd = 'lsblk --path -d -o name,rota --json'
    child = Popen(shlex.split(lsblk_cmd), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = child.communicate()
    out = out.strip()
    if child.returncode != 0 or not out:
        print("{0}Ran cmd: {1}".format(INFO, lsblk_cmd))
        if err:
            if isinstance(err, bytes) is True:
                err = err.decode()
            print("{0}{1}".format(ERRO, err))
            if 'unrecognized option' in err and '--json' in err:
                print("{}It seems lsblk version on localhost ".format(ERRO) +
                      "is too low to support json format")
        print("{}Failed to get storage device from localhost".format(ERRO))
        print("{0}Please manually populate {1}".format(INFO, STORDEV_FL))
        return {}
    if isinstance(out, bytes) is True:
        out = out.decode()
    try:
        lsblk_kv = json.loads(out)
        block_devs = lsblk_kv['blockdevices']
    except BaseException as e:
        print("{0}Tried to get 'blockdevices' but hit exception: {1}".format(
              ERRO, e))
        print("{0}Please manually populate {1}".format(INFO, STORDEV_FL))
        return {}

    dev_kv = {}
    for drive_kv in block_devs:
        if boot_devs:
            if drive_kv['name'] in boot_devs:
                continue
        if drive_kv['rota'] == '1' and '/dev/sd' in drive_kv['name']:
            dev_kv.update({drive_kv['name']: 'HDD'})
        elif drive_kv['rota'] == '0' and '/dev/sd' in drive_kv['name']:
            dev_kv.update({drive_kv['name']: 'SSD'})
        elif '/dev/nvme' in drive_kv['name']:
            dev_kv.update({drive_kv['name']: 'NVME'})
    if not dev_kv:
        print("{}It seems localhost has no storage device ".format(ERRO))
        print("{0}Please manually populate {1}".format(INFO, STORDEV_FL))
    return dev_kv


def ns_to_ms(ns):
    """
    Params:
        ns: nanoseconds
    Returns:
        milliseconds if succeeded.
        exit if hit error.
    """
    if isinstance(ns, float) is False and isinstance(ns, int) is False:
        sys.exit("{}Invalid parameter: ns\n".format(QUIT))
    if not ns:
        sys.exit("{}Empty parameter: ns\n".format(QUIT))
    try:
        ms = float(ns / 1000000.0)
        ms = float("{:.2f}".format(ms))
        return ms
    except BaseException as e:
        sys.exit("{}Tried to convert nanoseconds to milliseconds ".format(QUIT) +
              "but hit exception: {}\n".format(e))


def KiB_to_MiB(kib):
    """
    Params:
        kib: kibibyte
    Returns:
        mebibyte if succeeded.
        exit if hit error.
    """
    if isinstance(kib, float) is False and isinstance(kib, int) is False:
        sys.exit("{}Invalid parameter: kib\n".format(QUIT))
    if not kib:
        sys.exit("{}Empty parameter: kib\n".format(QUIT))
    try:
        mib = float(kib / 1024.0)
        mib = float("{:.2f}".format(mib))
        return mib
    except BaseException as e:
        sys.exit("{}Tried to convert kibibyte to mebibyte ".format(QUIT) +
              "but hit exception: {}\n".format(e))


def calc_diff_pct(data_set):
    """
    Params:
        data_set: a list with a series of number.
    Returns:
        The difference in percentage of the list.
        Which is defined as: 100 * (Max - Min) / Max.
        -1 if hit error.
    """
    if not data_set or isinstance(data_set, list) is False:
        print("{}Invalid parameter: data_set".format(ERRO))
        return -1

    try:
        max_val = max(data_set)
        min_val = min(data_set)
        raw_diff_pct = 100 * (max_val - min_val) / max_val
        diff_pct = float("{:.2f}".format(raw_diff_pct))
    except BaseException as e:
        print("{}Tried to calculate difference percentage ".format(ERRO) +
              "but hit exception: {}".format(e))
        return -1
    return diff_pct


def show_write_warning():
    """
    Params:
    Returns:
        0 if succeeded.
        Exit directly if hit error or data corruption is not allowed.
    """
    print('')
    print("{}Random write I/O type was enabled. It will ".format(WARN) +
          "corrupt data on storage devices")
    print("{}For above devices, double check if Operation ".format(WARN) +
          "System was NOT installed on")
    print("{}For above devices, double check if user data ".format(WARN) +
          "has been backed up")
    print('')
    print("{}Type 'I CONFIRM' to allow data on storage ".format(RED) +
          "devices to be corrupted. Otherwise, exit{}".format(RESETCOLOR))
    try:
        choice = input('Confirm? <I CONFIRM>: ')
    except KeyboardInterrupt as e:
        sys.exit("\n{0}Hit KeyboardInterrupt. Bye!\n".format(QUIT))
    if choice == 'I CONFIRM':
        print('')
        print("{}Type 'I CONFIRM' again to ensure you ".format(RED) +
              "allow data to be corrupted. Otherwise, exit{}".format(
              RESETCOLOR))
        try:
            second_choice = input('Confirm? <I CONFIRM>: ')
        except KeyboardInterrupt as e:
            sys.exit("\n{0}Hit KeyboardInterrupt. Bye!\n".format(QUIT))
        if second_choice == 'I CONFIRM':
            print('')
            return 0
        else:
            sys.exit("{}Leave the data as it is. Bye!\n".format(QUIT))
    else:
        sys.exit("{}Leave the data as it is. Bye!\n".format(QUIT))


def parse_arguments():
    """
    Params:
    Returns:
        {'guess_devices': bool, 'blocksize': str, 'numjobs': int,
         'runtime': int, 'io_type': str, 'skip_pkg_check': bool,
         'is_valid': str} if succeeded.
        {} if hit error.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-g", "--guess-devices",
        action="store_true",
        dest="guess_devices",
        help="guess the storage devices then overwrite them to " +
             "{0}. It is recommended to review {0}".format(
             os.path.basename(STORDEV_FL)) +
             " before starting storage readiness testing",
        default=False)

    parser.add_argument(
        "-b", "--block-size",
        action="store",
        dest="block_size",
        help="block size in bytes used for fio I/O units. " +
             "The default I/O block size is {} ".format(DEFAULT_BS) +
             "which is also for certification",
        #metavar="BLOCKSIZE",
        type=str.lower,
        choices=BS_CHOICES,
        default=DEFAULT_BS)

    parser.add_argument(
        "-j", "--job-per-device",
        action="store",
        dest="job_number",
        help="fio job number for each deivce. For certification, " +
             "it must be {}. This tool implies the 16 I/O ".format(
             DEFAULT_NJ) + "queue depth for each fio instance",
        metavar="JOBNUM",
        type=int,
        default=DEFAULT_NJ)

    parser.add_argument(
        "-t", "--runtime-per-instance",
        action="store",
        dest="fio_runtime",
        help="runtime in second for each fio instance. It should " +
             "be at least 30 sec even if ran quick testing. " +
             "For certification, it must be at least {0} ".format(
             DEFAULT_RT) + "sec",
        metavar="RUNTIME",
        type=int,
        default=DEFAULT_RT)

    parser.add_argument(
        "-w", "--random-write",
        action="store_true",
        dest="randwrite",
        help="use randwrite option to start fio instance instead of " +
             "randread. This would corrupt data that stored in the " +
             "storage devices. Ensure the original data on storage " +
             "devices has been backed up or could be corrupted " +
             "before specified this option",
        default=False)

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="Storage readiness {0}".format(VERSION))

    args = parser.parse_args()

    if args.fio_runtime < 30:
        print("{0}The specified {1} (< 30 sec) fio runtime ".format(ERRO,
              args.fio_runtime) + "is too short. Try a longer one")
        return {}

    ret_kv = {}
    ret_kv['guess_devices'] = args.guess_devices
    ret_kv['blocksize'] = args.block_size
    ret_kv['numjobs'] = args.job_number
    ret_kv['runtime'] = args.fio_runtime
    if args.randwrite is True:
        ret_kv['io_type'] = 'randwrite'
    else:
        ret_kv['io_type'] = 'randread'

    # KPIs are sized for randread 128k so we mark valid test OK for those only
    if args.block_size == '128k' and \
        args.fio_runtime >= int(DEFAULT_RT) and \
        args.job_number == int(DEFAULT_NJ) and \
        args.randwrite is False:
        ret_kv['is_valid'] = 'yes'
    else:
        ret_kv['is_valid'] = 'no'

    return ret_kv


def show_header():
    """
    Params:
    Returns:
        0 if succeeded.
    """
    print('')
    print("{0}Welcome to storage readiness tool, version ".format(GREEN) +
          "{0}{1}".format(VERSION, RESETCOLOR))
    print('')
    print("Please access {0} to get the latest version ".format(GIT_URL) +
          "or report issue(s)")
    print('')
    print("The purpose of this tool is to obtain drive metrics, then " +
          "compare them against certain KPIs")
    print('')
    print("{0}NOTE: This software absolutely comes with no ".format(RED) +
          "warranty of any kind. Use it at your own risk.{0}".format(RESETCOLOR))
    print("{0}      The IOPS and latency numbers shown are ".format(RED) +
          "under special parameters. That is not a generic storage " +
          "standard.{0}".format(RESETCOLOR))
    print("{0}      The numbers do not reflect any specification ".format(RED) +
          "of IBM Storage Scale or any performance number of user's " +
          "workload.{0}".format(RESETCOLOR))
    print('')
    return 0

class StorageReadiness():
    """
    A class to do storage readiness testing.
    """
    def __init__(self, kvs):
        """
        Params:
            kvs: a series of key-value pairs.
                Like: {
                'guess_devices': bool, 'blocksize': str,
                'numjobs': int, 'runtime': int, 'io_type': str,
                'skip_pkg_check': bool, 'is_valid': str}
        Returns:
            None.
            Exit if hit error.
        """
        if not kvs or isinstance(kvs, dict) is False:
            sys.exit("{}Invalid parameter: kvs".format(QUIT))
        try:
            guess_dev = kvs['guess_devices']
            runtime = kvs['runtime']
            io_type = kvs['io_type']
            blocksize = kvs['blocksize']
            numjobs = kvs['numjobs']
            is_valid = kvs['is_valid']
        except KeyError as e:
            sys.exit("{0}Tried to extract values from parameter ".format(QUIT) +
                     "but hit KeyError: {0}\n".format(e))
        # Thresholds
        self.__min_runtime = 300
        self.__min_iodepth = 16
        # Default fio options
        self.__invalidate = 1
        self.__engine = 'libaio'
        self.__ramp_time = 10
        self.__dir_buf = '-direct=1'
        # Comment out default io_size, it is too small
        #self.__io_size = 268435456
        self.__offset = 4802187264
        self.__output_format = 'json'
        self.__stordevfile = STORDEV_FL
        self.__kpifile = os.path.join(BASEDIR, 'randread_128KiB_16iodepth_KPIs.json')
        timestr = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_dir = os.path.join(BASEDIR, 'log', timestr)
        self.logdir = log_dir

        init_stor_devs = {}
        init_stor_devs['HDD'] = []
        init_stor_devs['SSD'] = []
        init_stor_devs['NVME'] = []
        init_stor_devs['ALL'] = []
        self._stor_devs = init_stor_devs
        self._kpis = {}
        self._guessdev = guess_dev
        self._runtime = runtime
        self.iotype = io_type
        self._blocksize = blocksize
        self._job_per_dev = numjobs
        self._isvalid = is_valid
        self._sing_perf = {}
        self._mult_perf = {}

    def initialize_storage_devices(self):
        """
        Params:
        Returns:
            0 if succeeded.
            1 if hit error.
        """
        dev_kv = {}
        if self._guessdev is True:
            dev_kv = guess_storage_devices()
            if not dev_kv:
                return 1
            if os.access(self.__stordevfile, os.W_OK) is False:
                print("{0}{1} does not have write permission".format(ERRO,
                      self.__stordevfile))
                return 1
            rc = dump_json(dev_kv, self.__stordevfile)
            if rc != 0:
                return 1
        else:
            print("{0}Extract storage device(s) from {1}".format(INFO,
                  os.path.basename(self.__stordevfile)))
            rc = is_file_readable(self.__stordevfile)
            if rc != 'yes':
                return 1
            dev_kv = load_json(self.__stordevfile)
            if dev_kv is None:
                return 1
        if not dev_kv:
            print("{0}Failed to load storage devices from {1}".format(ERRO,
                  self.__stordevfile))
            return 1
        print('')
        print("{0}Got below storage devices to be tested".format(INFO))
        hdds = []
        ssds = []
        nvms = []
        alldevs = []
        blk_count = 0
        none_blk_count = 0
        for dev, dev_type in dev_kv.items():
            devtype = dev_type.upper()
            if devtype not in ('HDD', 'SSD', 'NVME'):
                print("{0}{1} device type does not supported. ".format(ERRO,
                      dev_type))
                print("{0}Please re-write {1} refer to template".format(ERRO,
                      self.__stordevfile))
                return 1
            try:
                isblk = S_ISBLK(os.stat(dev).st_mode)
            except FileNotFoundError as e:
                print("{0}Tried to get block info of {1} but ".format(ERRO, dev) +
                      "hit FileNotFoundError: {}".format(e))
                print("{0}Please review then modify {1}".format(ERRO,
                      self.__stordevfile))
                return 1
            if isblk is True:
                print("{0}{1} {2} is a block device".format(INFO, dev_type, dev))
                blk_count += 1
                if devtype == 'HDD':
                    hdds.append(dev)
                elif devtype == 'SSD':
                    ssds.append(dev)
                elif devtype == 'NVME':
                    nvms.append(dev)
                alldevs.append(dev)
            else:
                print("{0}{1} {2} is NOT a block device".format(INFO, dev_type, dev))
                none_blk_count += 1
        if none_blk_count > 0 or blk_count == 0:
            print("{}None block device found. Please check device(s) ".format(ERRO) +
                  "in {}".format(self.__stordevfile))
            return 1
        elif blk_count == 1:
            print("{0}Above storage device is block device".format(INFO))
        else:
            print("{0}Above storage devices are all block devices".format(INFO))
        print('')
        if hdds:
            self._stor_devs['HDD'] = hdds
        if ssds:
            self._stor_devs['SSD'] = ssds
        if nvms:
            self._stor_devs['NVME'] = nvms
        if alldevs:
            self._stor_devs['ALL'] = alldevs
        if not self._stor_devs:
            print("{0}Failed to initialize storage devices".format(ERRO))
            return 1
        return 0

    def initialize_KPIs(self):
        """
        Params:
        Returns:
            0 if succeeded.
            1 if hit error.
        """
        rc = is_file_readable(self.__kpifile)
        if rc != 'yes':
            print("{0}Invalid file to describe certification ".format(ERRO) +
                  "KPIs is required")
            return 1
        kpi_kv = load_json(self.__kpifile)
        if kpi_kv is None:
            print("{0}Failed to load KPIs from {1}".format(ERRO, self.__kpifile))
            return 1
        print("{0}Extracted KPIs from {1} with version {2}".format(INFO,
              os.path.basename(self.__kpifile), kpi_kv['json_version']))
        self._kpis = kpi_kv
        return 0

    def estimate_time_consumption(self):
        """
        Params:
        Returns:
            Total time consumption in minute estimated for all testings.
            -1 if hit error.
        """
        try:
            hdds = self._stor_devs['HDD']
            ssds = self._stor_devs['SSD']
            nvms = self._stor_devs['NVME']
        except KeyError:
            pass
        hdd_num = len(hdds)
        ssd_num = len(ssds)
        nvme_num = len(nvms)
        instance_num = hdd_num + ssd_num + nvme_num
        if instance_num <= 0:
            print("{}Failed to estimate time. It seems no storage ".format(ERRO) +
                  "device to be tested")
            return -1
        if hdd_num > 1:
            instance_num += 1
        if ssd_num > 1:
            instance_num += 1
        if nvme_num > 1:
            instance_num += 1

        total_runtime = instance_num * self._runtime
        total_ramptime = instance_num * self.__ramp_time
        total_instancetime = total_runtime + total_ramptime
        total_instance_minutes = int(ceil(total_instancetime / 60.))
        if total_instance_minutes <= 0:
            print("{}It seems the runtime is too short to estimate ".format(ERRO) +
                  "total time consumption")
            return -1
        return total_instance_minutes

    def check_arguments(self, estimated_time):
        """
        Params:
            estimated_time: time in miniute.
        Returns:
            0 if succeeded.
            1 if hit error.
            Exit if type 'no'
        """
        if not estimated_time or isinstance(estimated_time, int) is False:
            print("{}Invalid parameter: estimated_time".format(ERRO))
            return 1
        if self._runtime >= self.__min_runtime:
            print("{0}The {1} sec runtime per fio instance is ".format(INFO,
                  self._runtime) + "sufficient to do storage certification")
        else:
            print("{0}The {1} sec runtime per fio instance is ".format(WARN,
                  self._runtime) + "not sufficient to certify storage " +
                  "devices")

        if self._blocksize.lower() == '128k':
            print("{}The 128KiB blocksize for each I/O unit is ".format(INFO) +
                  "valid to do storage certification")
        else:
            print("{0}The {1} blocksize for each I/O unit is ".format(WARN,
                  self._blocksize) + "invalid to certify storage devices")

        if self._job_per_dev == 1:
            print("{}The 1 fio job number for each storage ".format(INFO) +
                  "device is valid to do storage certification")
        else:
            print("{0}The {1} fio job number for storage device(s) ".format(WARN,
                  self._job_per_dev) + "is invalid to certify storage devices")

        if self.iotype == 'randread':
            print("{0}The {1} I/O type is valid to do storage ".format(INFO,
                  self.iotype) + "certification")
        else:
            print("{0}The {1} I/O type is invalid ".format(WARN, self.iotype) +
                  "to certify storage devices")

        print("{}The total time consumption of running this ".format(INFO) +
              "storage readiness instance is estimated to take " +
              "{0}~{1} minutes{2}".format(PURPLE, estimated_time, RESETCOLOR))

        print("{}Please check above messages, especially the ".format(INFO) +
              "storage devices to be tested")
        print("Type 'yes' to continue testing, 'no' to stop")
        while True:
            try:
                original_choice = input('Continue? <yes|no>: ')
            except KeyboardInterrupt as e:
                sys.exit("\n{0}Hit KeyboardInterrupt. Bye!\n".format(QUIT))
            if not original_choice:
                print("{}Pressing the Enter key does not supported. ".format(RED) +
                      "Please explicitly type 'yes' or 'no'{}".format(RESETCOLOR))
                continue
            choice = original_choice.lower()
            if choice == 'yes':
                print('')
                return 0
            elif choice == 'no':
                sys.exit("{0}Your choice is '{1}'. Bye!\n".format(QUIT,
                         original_choice))
            else:
                print("{0}Your choice is '{1}'. ".format(RED, original_choice) +
                      " Type 'yes' to continue, 'no' to stop{}".format(RESETCOLOR))
                continue
        print('')
        return 0

    def run_fio_instance(self, dev_to_test, remark):
        """
        Params:
            dev_to_test: storage devices to be tested.
            remark: comment for this fio instance.
        Returns:
            0 if succeeded.
            1 if hit error.
        """
        rc = 0
        if not dev_to_test or isinstance(dev_to_test, str) is False:
            print("{0}Invalid parameter: dev_to_test".format(ERRO))
            rc = 1
        if not remark or isinstance(remark, str) is False:
            print("{0}Invalid parameter: remark".format(ERRO))
            rc = 1
        dev_to_test = dev_to_test.strip()
        if '/dev/' not in dev_to_test or ' ' in dev_to_test:
            print("{0}Device in parameter dev_to_test is invalid".format(ERRO))
            rc = 1
        if rc != 0:
            return rc

        raw_devs = dev_to_test.split(':')
        # Remove the null character element
        devs = [x for x in raw_devs if x]
        dev_num = len(devs)
        numjobs = self._job_per_dev * dev_num

        if remark.upper() in ('HDD', 'SSD', 'NVME'):
            verb_remark = "all {0} devices".format(remark.upper())
        else:
            verb_remark = remark

        print("{0}Start fio instance with {1} I/O type, {2} I/O ".format(INFO,
              self.iotype, self._blocksize) + "blocksize, {} ".format(
              numjobs) + "job(s), against {0}, runtime {1} sec, ".format(
              verb_remark, self._runtime) + "ramp time {} sec".format(
              self.__ramp_time))
        print("{}Please wait for the instance to complete".format(INFO))
        name = "{0}_{1}_{2}".format(remark, self.iotype, self._blocksize)
        # Comment out "--io_size={} ".format(self.__iosize) + \
        fio_cmd = \
            "fio --ioengine={} ".format(self.__engine) + \
            "{} ".format(self.__dir_buf) + \
            "--rw={} ".format(self.iotype) + \
            "--invalidate={} ".format(self.__invalidate) + \
            "--iodepth={} ".format(self.__min_iodepth) + \
            "--numjobs={} ".format(numjobs) + \
            "--bs={} ".format(self._blocksize) + \
            "--offset={} ".format(self.__offset) + \
            "--stonewall --time_based " + \
            "--ramp_time={} ".format(self.__ramp_time) + \
            "--runtime={} ".format(self._runtime) + \
            "--filename={} ".format(dev_to_test) + \
            "--name={} ".format(name) + \
            "--minimal --group_reporting " + \
            "--output-format={} ".format(self.__output_format) + \
            "--output={0}/{1}.json".format(self.logdir, name)

        child = Popen(shlex.split(fio_cmd), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = child.communicate()
        if child.returncode != 0:
            print("{0}Failed to run cmd: {1}".format(ERRO, fio_cmd))
            if err:
                if isinstance(err, bytes) is True:
                    err = err.decode()
                print("{0}{1}".format(ERRO, err))
            return 1
        if out:
            if isinstance(out, bytes) is True:
                out = out.decode()
            print("{0}{1}".format(INFO, out))
        print("{0}{1} fio instance with {2} I/O blocksize, ".format(INFO,
              self.iotype, self._blocksize) + "against {0}, ".format(verb_remark) +
              "has completed")
        return 0

    def run_single_dev_tests(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        rc = 0
        try:
            alldevs = self._stor_devs['ALL']
        except KeyError as e:
            print("{}Tried to extract all storage devices from ".format(ERRO) +
                  "{0} but hit KeyError: {1}".format(self._stor_devs, e))
            rc = 1
        if not alldevs:
            print("{0}No storage device found".format(ERRO))
            rc = 1
        if rc != 0:
            return rc

        for dev in alldevs:
            remark = dev.split('/')[-1]
            rc = self.run_fio_instance(dev, remark)
            if rc != 0:
                print("{0}Hit error while running test against {1}".format(ERRO,
                      dev))
                return rc
        print("{0}Single storage device tests completed".format(INFO))
        print('')
        return 0

    def run_multilpe_dev_tests(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        for devtype in ['HDD', 'SSD', 'NVME']:
            try:
                devs = self._stor_devs[devtype]
            except KeyError as e:
                print("{0}Tried to extract devices from {1} ".format(ERRO,
                      self._stor_devs) + " by device type but hit KeyError: " +
                      "{}".format(e))
                return 1
            if len(devs) > 1:
                dev_to_test = ':'.join(devs)
                rc = self.run_fio_instance(dev_to_test, devtype)
                if rc != 0:
                    print("{0}Failed to run test against all {1} ".format(ERRO,
                          devtype) + "storage devices")
                    return rc

        print("{}Multiple storage device tests completed".format(INFO))
        print('')
        return 0

    def extract_single_dev_result(self):
        """
        Params:
        Returns:
            0 if succeeded.
            1 if hit error.
        Remarks:
            Assign {caseName1: {'drop_ios': num,
                                'iops': {'general': num, 'min': num,
                                         'mean': num, 'stddev': num},
                                'clat': {'min': num, 'max': num,
                                         'mean': num, 'stddev': num}}
            to self._sing_perf if succeeded.
        """
        if self.iotype == 'randwrite':
            rwstr = 'write'
        elif self.iotype == 'randread':
            rwstr = 'read'
        else:
            print("{0}{1} I/O type does not supported currently".format(ERRO,
                  self.iotype))
            return 1

        try:
            alldevs = self._stor_devs['ALL']
        except KeyError as e:
            print("{}Tried to get all storage devices from ".format(ERRO) +
                  "{} but hit KeyError: {}".format(self._stor_devs, e))
            return 1

        perf_kv = {}
        for dev in alldevs:
            name = "{0}_{1}_{2}".format(dev.split('/')[-1], self.iotype,
                   self._blocksize)
            outfile = "{0}/{1}.json".format(self.logdir, name)
            json_obj = load_json(outfile)
            if json_obj is None:
                return 1
            perf_kv[name] = {}
            # Drop I/Os
            try:
                drop_ios = json_obj['jobs'][0][rwstr]['drop_ios']
            except KeyError as e:
                print("{}Tried to extract drop_ios but hit KeyError: ".format(ERRO) +
                      "{}".format(e))
                return 1
            perf_kv[name]['drop_ios'] = int(drop_ios)
            # IOPS
            try:
                iops = json_obj['jobs'][0][rwstr]['iops']
                iops_min = json_obj['jobs'][0][rwstr]['iops_min']
                iops_mean = json_obj['jobs'][0][rwstr]['iops_mean']
                iops_stddev = json_obj['jobs'][0][rwstr]['iops_stddev']
            except KeyError as e:
                print("{}Tried to extract IOPS numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            try:
                perf_kv[name]['iops'] = {}
                perf_kv[name]['iops']['general'] = float("{:.2f}".format(iops))
                perf_kv[name]['iops']['min'] = float("{:.2f}".format(iops_min))
                perf_kv[name]['iops']['mean'] = float("{:.2f}".format(iops_mean))
                perf_kv[name]['iops']['stddev'] = float("{:.2f}".format(iops_stddev))
            except BaseException as e:
                print("{}Tried to save IOPS numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            # Latency
            try:
                clat_min = json_obj['jobs'][0][rwstr]['clat_ns']['min']
                clat_max = json_obj['jobs'][0][rwstr]['clat_ns']['max']
                clat_mean = json_obj['jobs'][0][rwstr]['clat_ns']['mean']
                clat_stddev = json_obj['jobs'][0][rwstr]['clat_ns']['stddev']
            except KeyError as e:
                print("{}Tried to extract latency numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            try:
                perf_kv[name]['clat'] = {}
                perf_kv[name]['clat']['min'] = ns_to_ms(clat_min)
                perf_kv[name]['clat']['max'] = ns_to_ms(clat_max)
                perf_kv[name]['clat']['mean'] = ns_to_ms(clat_mean)
                perf_kv[name]['clat']['stddev'] = ns_to_ms(clat_stddev)
            except KeyError as e:
                print("{}Tried to save latency numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            if self._blocksize in ['1m', '2m']:
                # Bandwidth
                try:
                    bw_min = json_obj['jobs'][0][rwstr]['bw_min']
                    bw_mean = json_obj['jobs'][0][rwstr]['bw_mean']
                except KeyError as e:
                    print("{}Tried to extract BW numbers but hit ".format(ERRO) +
                          "KeyError: {}".format(e))
                    return 1
                try:
                    perf_kv[name]['bw'] = {}
                    perf_kv[name]['bw']['min'] = "{} MiB/s".format(KiB_to_MiB(
                                                 bw_min))
                    perf_kv[name]['bw']['mean'] = "{} MiB/s".format(KiB_to_MiB(
                                                  bw_mean))
                except BaseException as e:
                    print("{}Tried to save BW numbers but hit ".format(ERRO) +
                          "KeyError: {}".format(e))
                    return 1

        if not perf_kv:
            print("{}Failed to extract performance numbers from fio ".format(ERRO) +
                  "output file in {}".format(self.logdir))
            return 1
        self._sing_perf = perf_kv
        return 0

    def extract_mult_dev_result(self):
        """
        Params:
        Returns:
            0 if succeeded.
            1 if hit error.
        Remarks:
            Assign {caseName1: {'drop_ios': num,
                                'iops': {'general': num, 'min': num,
                                         'mean': num, 'stddev': num},
                                'clat': {'min': num, 'max': num,
                                         'mean': num, 'stddev': num}}
            to self._mult_perf if succeeded.
        """
        if self.iotype == 'randwrite':
            rwstr = 'write'
        elif self.iotype == 'randread':
            rwstr = 'read'
        else:
            print("{0}{1} I/O type does not supported currently".format(ERRO,
                  self.iotype))
            return 1

        try:
            hdds = self._stor_devs['HDD']
            ssds = self._stor_devs['SSD']
            nvms = self._stor_devs['NVME']
        except KeyError:
            pass
        dev_types = []
        if len(hdds) > 1:
            dev_types.append('HDD')
        if len(ssds) > 1:
            dev_types.append('SSD')
        if len(nvms) > 1:
            dev_types.append('NVME')
        if not dev_types:
            print("{0}Failed to generate device type list".format(ERRO))
            return 1

        perf_kv = {}
        for dev_type in dev_types:
            name = "{0}_{1}_{2}".format(dev_type, self.iotype, self._blocksize)
            outfile = "{0}/{1}.json".format(self.logdir, name)
            json_obj = load_json(outfile)
            if json_obj is None:
                return 1
            perf_kv[name] = {}
            # Drop I/Os
            try:
                drop_ios = json_obj['jobs'][0][rwstr]['drop_ios']
            except KeyError as e:
                print("{}Tried to extract drop_ios but hit KeyError: ".format(ERRO) +
                      "{}".format(e))
                return 1
            perf_kv[name]['drop_ios'] = int(drop_ios)
            # IOPS
            try:
                iops = json_obj['jobs'][0][rwstr]['iops']
                iops_min = json_obj['jobs'][0][rwstr]['iops_min']
                iops_mean = json_obj['jobs'][0][rwstr]['iops_mean']
                iops_stddev = json_obj['jobs'][0][rwstr]['iops_stddev']
            except KeyError as e:
                print("{}Tried to extract IOPS numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            try:
                perf_kv[name]['iops'] = {}
                perf_kv[name]['iops']['general'] = float("{:.2f}".format(iops))
                perf_kv[name]['iops']['min'] = float("{:.2f}".format(iops_min))
                perf_kv[name]['iops']['mean'] = float("{:.2f}".format(iops_mean))
                perf_kv[name]['iops']['stddev'] = float("{:.2f}".format(iops_stddev))
            except BaseException as e:
                print("{}Tried to save IOPS numbers but hit KeyError: ".format(ERRO) +
                      "{}".format(e))
                return 1
            # Latency
            try:
                clat_min = json_obj['jobs'][0][rwstr]['clat_ns']['min']
                clat_max = json_obj['jobs'][0][rwstr]['clat_ns']['max']
                clat_mean = json_obj['jobs'][0][rwstr]['clat_ns']['mean']
                clat_stddev = json_obj['jobs'][0][rwstr]['clat_ns']['stddev']
            except KeyError as e:
                print("{}Tried to extract latency numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            try:
                perf_kv[name]['clat'] = {}
                perf_kv[name]['clat']['min'] = ns_to_ms(clat_min)
                perf_kv[name]['clat']['max'] = ns_to_ms(clat_max)
                perf_kv[name]['clat']['mean'] = ns_to_ms(clat_mean)
                perf_kv[name]['clat']['stddev'] = ns_to_ms(clat_stddev)
            except KeyError as e:
                print("{}Tried to save latency numbers but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
                return 1
            if self._blocksize in ['1m', '2m']:
                # Bandwidth
                try:
                    bw_min = json_obj['jobs'][0][rwstr]['bw_min']
                    bw_mean = json_obj['jobs'][0][rwstr]['bw_mean']
                except KeyError as e:
                    print("{}Tried to extract BW numbers but hit ".format(ERRO) +
                          "KeyError: {}".format(e))
                    return 1
                try:
                    perf_kv[name]['bw'] = {}
                    perf_kv[name]['bw']['min'] = "{:.2f} MiB/s".format(KiB_to_MiB(
                                                 bw_min))
                    perf_kv[name]['bw']['mean'] = "{:.2f} MiB/s".format(KiB_to_MiB(
                                                  bw_mean))
                except BaseException as e:
                    print("{}Tried to save BW numbers but hit ".format(ERRO) +
                          "KeyError: {}".format(e))
                    return 1

        if not perf_kv:
            print("{}Failed to extract performance numbers from ".format(ERRO) +
                  "fio output file in {}".format(self.logdir))
            return 1
        self._mult_perf = perf_kv
        return 0

    def compare_single_result_with_KPIs(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        print("{}Check if performance numbers of single storage ".format(INFO) +
              "device meet the required KPIs")
        print('')
        for devtype in ['HDD', 'SSD', 'NVME']:
            devs = self._stor_devs[devtype]
            if not devs:
                continue
            try:
                drop_ios_kpi = self._kpis[devtype]['drop_ios']
                min_iops_kpi = self._kpis[devtype]['iops']['min']
                mean_iops_kpi = self._kpis[devtype]['iops']['mean']
                max_clat_kpi = self._kpis[devtype]['clat']['max']
                mean_clat_kpi = self._kpis[devtype]['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get {1} KPIs but hit KeyError: ".format(ERRO,
                      devtype) + "{}".format(e))
                return 1

            err_cnt = 0
            for dev in devs:
                name = "{}_randread_128k".format(dev.split('/')[-1])
                try:
                    drop_ios = self._sing_perf[name]['drop_ios']
                    min_iops = self._sing_perf[name]['iops']['min']
                    mean_iops = self._sing_perf[name]['iops']['mean']
                    max_clat = self._sing_perf[name]['clat']['max']
                    mean_clat = self._sing_perf[name]['clat']['mean']
                except KeyError as e:
                    print("{0}Tried to get performance number of {1} ".format(ERRO,
                          name) + "but hit KeyError: {}".format(e))
                    return 1
                if drop_ios > drop_ios_kpi:
                    print("{0}{1} has {2} drop I/O(s) which is ".format(ERRO, dev,
                          drop_ios) + "over the required {} ".format(drop_ios_kpi) +
                          "drop I/O KPI of {}".format(devtype))
                    err_cnt += 1
                else:
                    print("{0}{1} has {2} drop I/O which meets ".format(INFO, dev,
                          drop_ios) + "the required {} ".format(drop_ios_kpi) +
                          "drop I/O KPI of {}".format(devtype))
                if min_iops < min_iops_kpi:
                    print("{0}{1} has {2} minimum IOPS which is ".format(ERRO, dev,
                          min_iops) + "below the required {} minimum".format(
                          min_iops_kpi) + "IOPS KPI of {}".format(devtype))
                    err_cnt += 1
                else:
                    print("{0}{1} has {2} minimum IOPS which ".format(INFO, dev,
                          min_iops) + "meets the required {} minimum ".format(
                          min_iops_kpi) + "IOPS KPI of {}".format(devtype))
                if mean_iops < mean_iops_kpi:
                    print("{0}{1} has {2} mean IOPS which ".format(ERRO, dev,
                          mean_iops) + "is below the required {} mean ".format(
                          mean_iops_kpi) + "IOPS KPI of {}".format(devtype))
                    err_cnt += 1
                else:
                    print("{0}{1} has {2} mean IOPS which meets ".format(INFO, dev,
                          mean_iops) + "the required {} mean IOPS KPI ".format(
                          mean_iops_kpi) + "of {}".format(devtype))
                if max_clat > max_clat_kpi:
                    print("{0}{1} has {2} msec maximum latency which ".format(ERRO,
                          dev, max_clat) + "is over the required {} msec ".format(
                          max_clat_kpi) + "maximum latency KPI of {}".format(
                          devtype))
                    err_cnt += 1
                else:
                    print("{0}{1} has {2} msec maximum latency which ".format(INFO,
                          dev, max_clat) + "meets the required {} msec ".format(
                          max_clat_kpi) + "maximum latency KPI of {}".format(
                          devtype))
                if mean_clat > mean_clat_kpi:
                    print("{0}{1} has {2} msec mean latency which is ".format(ERRO,
                          dev, mean_clat) + "over the required {} msec ".format(
                          mean_clat_kpi) + "mean latency KPI of {}".format(
                          devtype))
                    err_cnt += 1
                else:
                    print("{0}{1} has {2} msec mean latency which ".format(INFO,
                          dev, mean_clat) + "meets the required {} msec ".format(
                          mean_clat_kpi) + "mean latency KPI of {}".format(
                          devtype))
                print('')
        return err_cnt

    def compare_multiple_results_with_KPIs(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        err_cnt = 0
        print("{}Check if performance numbers of multiple storage ".format(INFO) +
              "devices meet the required KPIs")
        print('')
        for devtype in ['HDD', 'SSD', 'NVME']:
            devnum = len(self._stor_devs[devtype])
            if devnum < 2:
                continue
            try:
                drop_ios_kpi = self._kpis[devtype]['drop_ios']
                min_iops_kpi = self._kpis[devtype]['iops']['min']
                mean_iops_kpi = self._kpis[devtype]['iops']['mean']
                max_clat_kpi = self._kpis[devtype]['clat']['max']
                mean_clat_kpi = self._kpis[devtype]['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get {1} KPIs but hit KeyError: ".format(ERRO,
                      devtype) + "{}".format(e))
                return 1
            name = "{}_randread_128k".format(devtype)
            try:
                drop_ios = self._mult_perf[name]['drop_ios']
                min_iops = self._mult_perf[name]['iops']['min']
                mean_iops = self._mult_perf[name]['iops']['mean']
                max_clat = self._mult_perf[name]['clat']['max']
                mean_clat = self._mult_perf[name]['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get performance number of {1} ".format(ERRO,
                      name) + "but hit KeyError: {}".format(e))
                return 1
            if drop_ios > drop_ios_kpi:
                print("{0}{1} has {2} drop I/O(s) which is over the ".format(ERRO,
                      devtype, drop_ios) + "required {} ".format(drop_ios_kpi) +
                      "drop I/O KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} drop I/O(s) which meets the ".format(INFO,
                      devtype, drop_ios) + "required {} ".format(drop_ios_kpi) +
                      "drop I/O KPI of {}".format(devtype))
            min_iops /= devnum
            min_iops = float("{:.2f}".format(min_iops))
            if min_iops < min_iops_kpi:
                print("{0}{1} has {2} average minimum IOPS which is ".format(ERRO,
                      devtype, min_iops) + "below the required {} ".format(
                      min_iops_kpi) + "minimum IOPS KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} average minimum IOPS which ".format(INFO,
                      devtype, min_iops) + "meets the required {} ".format(
                      min_iops_kpi) + "minimum IOPS KPI of {}".format(devtype))
            mean_iops /= devnum
            mean_iops = float("{:.2f}".format(mean_iops))
            if mean_iops < mean_iops_kpi:
                print("{0}{1} has {2} average mean IOPS which is ".format(ERRO,
                      devtype, mean_iops) + "below the required {} ".format(
                      mean_iops_kpi) + "mean IOPS KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} average mean IOPS which meets ".format(INFO,
                      devtype, mean_iops) + "the required {} mean IOPS ".format(
                      mean_iops_kpi) + "KPI of {}".format(devtype))
            if max_clat > max_clat_kpi:
                print("{0}{1} has {2} msec maximum latency which is ".format(ERRO,
                      devtype, max_clat) + "over the required {} msec ".format(
                      max_clat_kpi) + "maximum latency KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} msec maximum latency which ".format(INFO,
                      devtype, max_clat) + "meets the required {} msec ".format(
                      max_clat_kpi) + "maximum latency KPI of {}".format(devtype))
            if mean_clat > mean_clat_kpi:
                print("{0}{1} has {2} msec mean latency which is ".format(ERRO,
                      devtype, mean_clat) + "over the required {} msec ".format(
                      mean_clat_kpi) + "mean latency KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} msec mean latency which meets ".format(INFO,
                      devtype, mean_clat) + "the required {} msec mean ".format(
                      mean_clat_kpi) + "latency KPI of {}".format(devtype))
            print('')
        return err_cnt

    def show_single_dev_result_if_invalid(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        if not self._sing_perf or isinstance(self._sing_perf, dict) is False:
            print("{} No performance data for single storage device".format(ERRO))
            return 1
        try:
            alldevs = self._stor_devs['ALL']
        except KeyError as e:
            print("{0}Tried to get all storage devices from {1} ".format(ERRO,
                  self._stor_devs) + "but hit KeyError: {}".format(e))
            return 1

        for dev in alldevs:
            name = "{0}_{1}_{2}".format(dev.split('/')[-1], self.iotype,
                   self._blocksize)
            try:
                drop_ios = self._sing_perf[name]['drop_ios']
                min_iops = self._sing_perf[name]['iops']['min']
                mean_iops = self._sing_perf[name]['iops']['mean']
                max_clat = self._sing_perf[name]['clat']['max']
                mean_clat = self._sing_perf[name]['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get performance number of {1} but ".format(ERRO,
                      name) + "hit KeyError: {}".format(e))
                return 1
            print("{0}{1} has {2} {3} drop I/O(s)".format(INFO, dev, drop_ios,
                  self.iotype))
            print("{0}{1} has {2} minimum {3} IOPS ".format(INFO, dev, min_iops,
                  self.iotype))
            print("{0}{1} has {2} mean {3} IOPS ".format(INFO, dev, mean_iops,
                  self.iotype))
            print("{0}{1} has {2} msec maximum {3} latency".format(INFO, dev,
                  max_clat, self.iotype))
            print("{0}{1} has {2} msec mean {3} latency".format(INFO, dev,
                  mean_clat, self.iotype))
            if self._blocksize in ['1m', '2m']:
                try:
                    min_bw = self._sing_perf[name]['bw']['min']
                    mean_bw = self._sing_perf[name]['bw']['mean']
                except KeyError as e:
                    print("{}Tried to get bandwidth performance number ".format(
                          ERRO) + "of {0} but hit KeyError: {1}".format(name, e))
                    return 1
                print("{0}{1} has {2} minimum {3} bandwidth".format(INFO, dev,
                      min_bw, self.iotype))
                print("{0}{1} has {2} mean {3} bandwidth".format(INFO, dev,
                      mean_bw, self.iotype))
            print('')
        return 0

    def show_multiple_dev_results_if_invalid(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        if not self._mult_perf or isinstance(self._mult_perf, dict) is False:
            print("{} No performance data for multiple storage devices".format(ERRO))
            return 1

        for key, val in self._mult_perf.items():
            try:
                drop_ios = val['drop_ios']
                min_iops = val['iops']['min']
                mean_iops = val['iops']['mean']
                max_clat = val['clat']['max']
                mean_clat = val['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get performance number of {1} ".format(ERRO, key) +
                      "but hit KeyError: {}".format(e))
                return 1
            print("{0}{1} has {2} {3} drop I/O(s)".format(INFO, key, drop_ios,
                  self.iotype))
            print("{0}{1} has {2} minimum {3} IOPS".format(INFO, key, min_iops,
                  self.iotype))
            print("{0}{1} has {2} mean {3} IOPS".format(INFO, key, mean_iops,
                  self.iotype))
            print("{0}{1} has {2} msec maximum {3} latency".format(INFO, key,
                  max_clat, self.iotype))
            print("{0}{1} has {2} msec mean {3} latency".format(INFO, key,
                  mean_clat, self.iotype))
            if self._blocksize in ['1m', '2m']:
                try:
                    min_bw = val['bw']['min']
                    mean_bw = val['bw']['mean']
                except KeyError as e:
                    print("{}Tried to get bandwidth performance number ".format(
                          ERRO) + "of {0} but hit KeyError: {1}".format(key, e))
                    return 1
                print("{0}{1} has {2} minimum {3} bandwidth".format(INFO, key,
                      min_bw, self.iotype))
                print("{0}{1} has {2} mean {3} bandwidth".format(INFO, key,
                      mean_bw, self.iotype))
            print('')
        return 0

    def compare_peers(self):
        """
        Params:
        Returns:
            0 if succeeded.
            !0 if hit error.
        """
        try:
            diff_pct_kpi = self._kpis['max_diff_pct']
        except KeyError as e:
            print("{}Tried to extract maximum difference percentage ".format(ERRO) +
                  "from {0} but hit KeyError: {1}".format(self._kpis, e))
            return 1

        print("{}Define difference percentage as 100 * (max - min) / max".format(INFO))
        print("{}Check if difference percentage of IOPS and latency ".format(INFO) +
              "meets the KPI")
        print('')
        err_cnt = 0
        for devtype in ['HDD', 'SSD', 'NVME']:
            try:
                devs = self._stor_devs[devtype]
            except KeyError as e:
                print("{}Tried to extract certain type of device from ".format(ERRO) +
                      "{0} but hit KeyError: {1}".format(self._stor_devs, e))
                return 1
            dev_len = len(devs)
            if dev_len  < 2:
                print("{0}{1} device number is not enough to ".format(INFO, devtype) +
                      "do difference percentage checking")
                print('')
                continue
            mean_iopses = []
            mean_clats = []
            for dev in devs:
                name = "{}_randread_128k".format(dev.split('/')[-1])
                try:
                    mean_iops = self._sing_perf[name]['iops']['mean']
                    mean_clat = self._sing_perf[name]['clat']['mean']
                except KeyError as e:
                    print("{0}Tried to extract mean numbers of {1} but ".format(ERRO,
                          name) + "hit KeyError: {}".format(e))
                    return 1
                mean_iopses.append(mean_iops)
                mean_clats.append(mean_clat)

            if len(mean_iopses) != dev_len:
                print("{0}Length of mean IOPS list of {1} is incorrect".format(ERRO,
                      devtype))
                print('')
                err_cnt += 1
                continue
            if len(mean_clats) != dev_len:
                print("{0}Length of mean latency list of {1} is incorrect".format(ERRO,
                      devtype))
                print('')
                err_cnt += 1
                continue

            iops_diff_pct = calc_diff_pct(mean_iopses)
            if iops_diff_pct < 0:
                print('')
                err_cnt += 1
                continue
            clat_diff_pct = calc_diff_pct(mean_clats)
            if clat_diff_pct < 0:
                print('')
                err_cnt += 1
                continue

            if iops_diff_pct > diff_pct_kpi:
                print("{0}All {1}s have {2}% difference of IOPS ".format(INFO, devtype,
                      iops_diff_pct) + "which is over required {}% maximum ".format(
                      diff_pct_kpi) + "difference percentage KPI")
                err_cnt += 1
            else:
                print("{0}All {1}s have {2}% difference of IOPS ".format(INFO, devtype,
                      iops_diff_pct) + "which meets required {}% maximum ".format(
                      diff_pct_kpi) + "difference percentage KPI")
            if clat_diff_pct > diff_pct_kpi:
                print("{0}All {1}s have {2}% difference of latency which ".format(INFO,
                      devtype, clat_diff_pct) + "is over required {}% maximum ".format(
                      diff_pct_kpi) + "difference percentage KPI")
                err_cnt += 1
            else:
                print("{0}All {1}s have {2}% difference of latency which ".format(INFO,
                      devtype, clat_diff_pct) + "meets required {}% maximum ".format(
                      diff_pct_kpi) + "difference percentage KPI")
            print('')
        return err_cnt

    def summarize_test_results(self):
        """
        Params:
        Returns:
            0 if succeeded.
            1 if hit error.
        """
        kpi_chk_err_cnt = 0
        if self._isvalid == 'yes':
            sin_com = self.compare_single_result_with_KPIs()
            if sin_com != 0:
                kpi_chk_err_cnt += 1
            mul_com = self.compare_multiple_results_with_KPIs()
            if mul_com != 0:
                kpi_chk_err_cnt += 1
            comp_rc = self.compare_peers()
            if comp_rc == 0:
                print("{}All types of storage devices passed the KPI ".format(INFO) +
                      "check")
            else:
                kpi_chk_err_cnt += 1
                print("{}Not all types of storage devices passed the ".format(INFO) +
                      "KPI check")
            print('')
            if kpi_chk_err_cnt == 0:
                print("{}All storage devices are ready to run the ".format(INFO) +
                      "next procedure\n")
                return 0
            else:
                print("{}*NOT* all storage devices are ready. Storage ".format(ERRO) +
                      "devices in this host *CANNOT* be used by IBM Storage Scale\n")
                return 1
        else:
            err_cnt = 0
            sing_rc = self.show_single_dev_result_if_invalid()
            err_cnt += sing_rc
            mult_rc = self.show_multiple_dev_results_if_invalid()
            err_cnt += mult_rc
            if err_cnt == 0:
                print("{}Performance of storage devices in this host ".format(ERRO) +
                      "have been tested. But this test instance is *invalid*\n")
            else:
                print("{}Storage devices in this host did not look ".format(ERRO) +
                      "good. Storage devices on this host *CANNOT* be used by IBM " +
                      "Storage Scale\n")
            return 1


def main():
    """
    Params:
    Returns:
        Exit if hit error.
    """
    arg_kv = parse_arguments()
    if not arg_kv:
        sys.exit("{}Bye!\n".format(QUIT))

    show_header()
    ss = StorageReadiness(arg_kv)

    rc = check_root_user()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    rc = ss.initialize_storage_devices()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))
    rc = ss.initialize_KPIs()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    time_cons = ss.estimate_time_consumption()
    if time_cons < 0:
        sys.exit("{}Bye!\n".format(QUIT))

    rc = ss.check_arguments(time_cons)
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    if ss.iotype == 'randwrite':
        show_write_warning()

    # fio can be installed from resouce code or rpm package
    rc = is_fio_available()
    if rc != 0:
        sys.exit("{0}Please ensure fio is installed and environment ".format(QUIT) +
                 "variable is exported\n")

    # Create LOG directory
    try:
        os.makedirs(ss.logdir)
    except BaseException as e:
        sys.exit("{0}Tried to create {1} but hit exception: {2}\n".format(QUIT,
                 ss.logdir, e))

    rc = ss.run_single_dev_tests()
    if rc != 0:
        sys.exit("{}Failed to run test against single storage device\n".format(
                 QUIT))

    rc = ss.run_multilpe_dev_tests()
    if rc != 0:
        sys.exit("{}Failed to run test against multiple storage devices\n".format(
                 QUIT))

    rc = ss.extract_single_dev_result()
    if rc != 0:
        sys.exit("{}Failed to extract result for single storage device\n".format(
                 QUIT))

    rc = ss.extract_mult_dev_result()
    if rc != 0:
        sys.exit("{0}Failed to extract result for multiple storage ".format(
                 QUIT) + "devices\n")

    return ss.summarize_test_results()


if __name__ == '__main__':
    main()
