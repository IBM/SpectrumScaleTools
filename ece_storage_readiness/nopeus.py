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
from collections import OrderedDict

RED = '\033[91m'
BOLDRED = '\033[91;1m'
BLUE = '\033[34m'
GREEN = '\033[92m'
PURPLE = '\033[35m'
YELLOW = '\033[93m'
RESETCOL = '\033[0m'

INFO = "[ {0}INFO{1}  ] ".format(GREEN, RESETCOL)
WARN = "[ {0}WARN{1}  ] ".format(YELLOW, RESETCOL)
ERRO = "[ {0}FATAL{1} ] ".format(RED, RESETCOL)
QUIT = "[ {0}QUIT{1}  ] ".format(RED, RESETCOL)

VERSION = "1.21"
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
KPI_FL = "{}/randread_128KiB_16iodepth_KPIs.json".format(BASEDIR)

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
            dict_obj = json.load(fh, object_pairs_hook=OrderedDict)
            return dict_obj
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
        print("{0}Tried to [over]write file {1} but ".format(ERRO,
              dst_file) + "hit exception: {}\n".format(e))
        return 1


def is_fio_available():
    """
    Params:
    Returns:
        0 if fio is available.
        1 if not.
    """
    try:
        child = Popen(shlex.split('fio -v'), stdin=PIPE, stdout=PIPE,
                      stderr=PIPE)
        out, err = child.communicate()
    except BaseException as e:
        print("{}Tried to run cmd 'fio -v' but hit ".format(ERRO) +
              "exception: {}".format(e))
        return 1
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
    print("{0}fio benchmark is available with version {1}".format(INFO,
          fio_ver))
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
    try:
        child = Popen(shlex.split('df -l'), stdin=PIPE, stdout=PIPE,
                      stderr=PIPE)
        out, err = child.communicate()
    except BaseException as e:
        print("{}Tried to run cmd 'df -l' but hit ".format(ERRO) +
              "exception: {}".format(e))
        return ['error']
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
    print("{}Guess testable storage device of localhost".format(INFO))
    #lsblk_cmd = 'lsblk --path -d -o name,rota --json'
    lsblk_cmd = 'lsblk --path -o name,rota,mountpoint --json'
    try:
        child = Popen(shlex.split(lsblk_cmd), stdin=PIPE, stdout=PIPE,
                      stderr=PIPE)
        out, err = child.communicate()
    except BaseException as e:
        print("{0}Tried to run cmd '{1}' but ".format(ERRO, lsblk_cmd) +
              "hit exception: {}".format(e))
        return {}
    out = out.strip()
    if child.returncode != 0 or not out:
        print("{0}Ran cmd: {1}".format(INFO, lsblk_cmd))
        if err:
            if isinstance(err, bytes) is True:
                err = err.decode()
            print("{0}{1}".format(ERRO, err))
            if 'unrecognized option' in err and '--json' in err:
                print("{}lsblk version on localhost is too ".format(ERRO) +
                      "low to support json format")
        print("{}Failed to get storage device from localhost".format(ERRO))
        print("{0}Please manually populate {1}".format(INFO, STORDEV_FL))
        return {}
    if isinstance(out, bytes) is True:
        out = out.decode()
    try:
        lsblk_kv = json.loads(out)
        block_devs = lsblk_kv['blockdevices']
    except BaseException as e:
        print("{}Tried to extract 'blockdevices' but ".format(ERRO) +
              "hit exception: {}".format(e))
        print("{0}Please manually populate {1}".format(INFO, STORDEV_FL))
        return {}

    dev_kv = OrderedDict()
    for drive_kv in block_devs:
        try:
            devname = drive_kv['name']
        except KeyError as e:
            print("{}Tried to extract device name but hit ".format(ERRO) +
                  "KeyError: {}".format(e))
            return {}
        if boot_devs:
            if devname in boot_devs:
                continue
        if '/dev/sd' in devname or '/dev/nvme' in devname:
            try:
                children = drive_kv['children']
                print("{0}{1} has been partitioned which might be ".format(WARN,
                      devname) + "used. Ignore it")
                continue
            except KeyError:
                pass
            try:
                mntpnt = drive_kv['mountpoint']
                if mntpnt is not None:
                    print("{0}{1} has been mounted which might be ".format(WARN,
                          devname) + "used. Ignore it")
                    continue
                dev_rota = drive_kv['rota']
            except KeyError as e:
                print("{}Tried to get mounting and rotation ".format(ERRO) +
                      "information but hit KeyError: {}".format(e))
                return {}
            if dev_rota == '1' or dev_rota is True:
                dev_kv.update({devname: 'HDD'})
            elif dev_rota == '0' or dev_rota is False:
                dev_kv.update({devname: 'SSD'})
            if '/dev/nvme' in devname:
                dev_kv.update({devname: 'NVME'})
        elif '/dev/vd' in devname:
            print("{0}{1} is not supported at this stage".format(WARN, devname))
    if not dev_kv:
        print("{}Localhost has no testable storage device".format(ERRO))
        print("{0}Please manually populate {1}. And ".format(INFO, STORDEV_FL) +
              "do not use '-g' or '--guess-devices' option")
    return dev_kv


def check_device(dev, dev_type):
    """
    Params:
        dev: storage device.
        dev_type: device type.
    Returns:
        (dev_ok, dev_size)
    """
    if not dev or isinstance(dev, str) is False:
        print("{}Invalid parameter: dev".format(ERRO))
        return 'error', ''
    if not dev_type or isinstance(dev_type, str) is False:
        print("{}Invalid parameter: dev_type".format(ERRO))
        return 'error', ''
    dev = dev.strip()
    if '/dev/sd' not in dev and '/dev/nvme' not in dev:
        print("{0}{1} is not supported at this stage".format(ERRO, dev))
        return 'error', ''
    dev_type = dev_type.strip()
    dev_type = dev_type.upper()
    if dev_type not in ['HDD', 'SSD', 'NVME']:
        print("{0}{1} device type is not supported at this ".format(ERRO,
              dev_type) + "stage")
        return 'error', ''
    cmd = "lsblk --path -o name,rota,mountpoint,size --json {}".format(dev)
    try:
        child = Popen(shlex.split(cmd), stdin=PIPE, stdout=PIPE,
                      stderr=PIPE)
        out, err = child.communicate()
    except BaseException as e:
        # lsblk might be out of date. Ignore this checking
        return 'ok', ''
    out = out.strip()
    if child.returncode != 0 or not out:
        print("{0}Ran cmd: {1}".format(INFO, cmd))
        if err:
            if isinstance(err, bytes) is True:
                err = err.decode()
            print("{0}{1}".format(ERRO, err))
        print("{0}Failed to get information of {1}".format(ERRO, dev))
        return 'error', ''
    if isinstance(out, bytes) is True:
        out = out.decode()
    try:
        lsblk_kv = json.loads(out)
        block_devs = lsblk_kv['blockdevices']
    except BaseException as e:
        print("{0}Tried to get 'blockdevices' of {1} but hit ".format(
              ERRO, dev) + "exception: {}".format(e))
        return 'error', ''
    if len(block_devs) != 1:
        print("{0}Got incorrect information of {1}".format(ERRO, dev))
        print("{0}{1}{2}".format(RED, out, RESETCOL))
        return 1
    err_cnt = 0
    warn_cnt = 0
    sz = ''
    for drive_kv in block_devs:
        if not drive_kv:
            print("{0}{1} does not exist".format(ERRO, dev))
            err_cnt += 1
            continue
        try:
            devname = drive_kv['name']
        except KeyError as e:
            print("{}Tried to extract device name but hit ".format(ERRO) +
                  "KeyError: {}".format(e))
            return 'error', ''
        devname = devname.strip()
        if devname != dev:
            print("{0}Real name of {1} is {2}".format(ERRO, dev, devname))
            err_cnt += 1
            continue
        try:
            children = drive_kv['children']
            print("{0}{1} has been partitioned which might ".format(WARN,
                  dev) + "be used")
            warn_cnt += 1
            continue
        except KeyError:
            pass
        try:
            mntpnt = drive_kv['mountpoint']
            if mntpnt is not None:
                print("{0}{1} has been mounted which might be ".format(WARN,
                      dev) + "used")
                warn_cnt += 1
                continue
            dev_rota = drive_kv['rota']
            sz = drive_kv['size']
        except KeyError as e:
            print("{0}Tried to get information of {1} but hit ".format(ERRO,
                  dev) + "KeyError: {}".format(e))
            return 'error', ''
        if '/dev/nvme' not in dev:
            if dev_rota == '1' or dev_rota is True:
                if dev_type != 'HDD':
                    print("{0}Detected {1} is HDD but ".format(ERRO, dev) +
                          "it was specified as {}".format(dev_type))
                    err_cnt += 1
                    continue
            elif dev_rota == '0' or dev_rota is False:
                if dev_type != 'SSD':
                    print("{0}Detected {1} is SSD but ".format(ERRO, dev) +
                          "it was specified as {}".format(dev_type))
                    err_cnt += 1
                    continue
        else:
            if dev_type != 'NVME':
                print("{0}Detected {1} is NVMe but it ".format(ERRO, dev) +
                      "was specified as {}".format(dev_type))
                err_cnt += 1
                continue
    if err_cnt != 0:
        return 'error', ''
    else:
        if warn_cnt != 0:
            return 'warn', sz
        else:
            return 'ok', sz


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
    print("{}Random write I/O type was enabled. It will ".format(BOLDRED) +
          "corrupt data in above storage device list{}".format(RESETCOL))
    print("{}In above storage device list, double check ".format(BOLDRED) +
          "that Operation System is NOT installed{}".format(RESETCOL))
    print("{}In above storage device list, double check ".format(BOLDRED) +
          "that user data has been backed up{}".format(RESETCOL))
    print('')
    print("{}Type 'I CONFIRM' to allow data on storage ".format(BOLDRED) +
          "devices to be corrupted. Otherwise, exit{}".format(RESETCOL))
    try:
        choice = input('Confirm? <I CONFIRM>: ')
    except KeyboardInterrupt as e:
        sys.exit("\n{0}Hit KeyboardInterrupt. Bye!\n".format(QUIT))
    if choice == 'I CONFIRM':
        print('')
        print("{}Type 'I CONFIRM' again to ensure you ".format(RED) +
              "allow data to be corrupted. Otherwise, exit{}".format(
              RESETCOL))
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
        "-g",
        "--guess-devices",
        action="store_true",
        dest="guess_devices",
        help="guess the storage devices then overwrite them to " +
             "{0}. It is recommended to review {0}".format(
             os.path.basename(STORDEV_FL)) +
             " before starting storage readiness testing",
        default=False)

    parser.add_argument(
        "-b",
        "--block-size",
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
        "-j",
        "--job-per-device",
        action="store",
        dest="job_number",
        help="fio job number for each deivce. For certification, " +
             "it must be {}. This tool implies the 16 I/O ".format(
             DEFAULT_NJ) + "queue depth for each fio instance",
        metavar="JOBNUM",
        type=int,
        default=DEFAULT_NJ)

    parser.add_argument(
        "-t",
        "--runtime-per-instance",
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
        "-w",
        "--random-write",
        action="store_true",
        dest="randwrite",
        help="use randwrite option to start fio instance instead of " +
             "randread. This would corrupt data that stored in the " +
             "storage devices. Ensure the original data on storage " +
             "devices has been backed up or could be corrupted " +
             "before specified this option",
        default=False)

    parser.add_argument(
        "-v",
        "--version",
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
    print("{0}Welcome to Storage Readiness {1}{2}".format(GREEN, VERSION,
          RESETCOL))
    print('')
    print("The purpose of this tool is to obtain storage device metrics " +
          "of localhost then compare them against certain KPIs")
    print("Please access {} to get required version and report ".format(
          GIT_URL) + "issue if necessary")
    print('')
    print("{0}NOTE:{1}".format(BOLDRED, RESETCOL))
    print("{}  This software absolutely comes with no warranty ".format(
          RED) + "of any kind. Use it at your own risk.{}".format(
          RESETCOL))
    print("{}  The IOPS and latency numbers shown are under ".format(RED) +
          "special parameters. That is not a generic storage standard." +
          "{}".format(RESETCOL))
    print("{}  The numbers do not reflect any specification ".format(RED) +
          "of IBM Storage Scale or any user workload running on it." +
          "{}".format(RESETCOL))
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
        self.__certify_bs = '128k'
        self.__certify_job = 1
        self.__certify_iotp = 'randread'
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
        self.__kpifile = KPI_FL
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
                print("{0}Please manually populate file {1} ".format(INFO,
                      self.__stordevfile) + "with storage devices of " +
                      "localhost")
                return 1
            if os.access(self.__stordevfile, os.W_OK) is False:
                print("{0}{1} does not have write permission".format(ERRO,
                      self.__stordevfile))
                return 1
            rc = dump_json(dev_kv, self.__stordevfile)
            if rc != 0:
                return 1
        else:
            print("{0}Extract storage device from {1}".format(INFO,
                  os.path.basename(self.__stordevfile)))
            rc = is_file_readable(self.__stordevfile)
            if rc != 'yes':
                return 1
            dev_kv = load_json(self.__stordevfile)
            if dev_kv is None:
                return 1
        if not dev_kv:
            print("{0}Failed to load storage device from {1}".format(ERRO,
                  self.__stordevfile))
            print("{}Please manually populate the file with ".format(INFO) +
                  "storage devices of localhost or use '-g' or " +
                  "'--guess-devices' option")
            print('')
            return 1
        print('')
        print("{0}Extract testable storage device list".format(INFO))
        hdds = []
        ssds = []
        nvms = []
        alldevs = []
        type_err_cnt = 0
        err_cnt = 0
        warn_cnt = 0
        for dev, dev_type in dev_kv.items():
            devtype = dev_type.upper()
            if self._guessdev is False and devtype not in ['HDD', 'SSD', 'NVME']:
                print("{0}{1} is {2} which device ".format(ERRO, dev, dev_type) +
                      "type does not supported")
                type_err_cnt += 1
                err_cnt += 1
                continue
            try:
                isblk = S_ISBLK(os.stat(dev).st_mode)
            except BaseException as e:
                print("{0}Tried to get block info of {1} but ".format(ERRO, dev) +
                      "hit exception : {}".format(e))
                err_cnt += 1
                continue
            if isblk is False:
                print("{0}{1} is NOT a block device".format(ERRO, dev))
                err_cnt += 1
                continue
            state, size = check_device(str(dev), str(dev_type))
            if state == 'error':
                err_cnt += 1
                continue
            if state == 'warn':
                warn_cnt += 1
            if size:
                print("{0}{1} is {2} and a block device. Its size ".format(INFO, dev,
                      dev_type) + "is {}".format(size))
            else:
                print("{0}{1} is {2} and a block device".format(INFO, dev, dev_type))
            if devtype == 'HDD':
                hdds.append(dev)
            elif devtype == 'SSD':
                ssds.append(dev)
            elif devtype == 'NVME':
                nvms.append(dev)
            alldevs.append(dev)
        if type_err_cnt != 0:
            print("{0}Please edit {1} refer to the example file".format(ERRO,
                  self.__stordevfile))
        if err_cnt != 0:
            print("{}Storage device which is not testable has ".format(ERRO) +
                  "been detected. Please review and edit {}".format(
                  self.__stordevfile))
            return 1
        else:
            if warn_cnt != 0:
                print("{0}Above storage device list has ".format(WARN) +
                      "warning to run test")
            else:
                print("{0}Above storage device list is OK ".format(INFO) +
                      "to be tested")
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
            print("{0}Failed to load KPIs from {1}".format(ERRO,
                  self.__kpifile))
            return 1
        print("{0}Extracted KPIs from {1} with version {2}".format(INFO,
              os.path.basename(self.__kpifile), kpi_kv['json_version']))
        print('')
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
            print("{}It seems the runtime is too short to ".format(ERRO) +
                  "estimate total time consumption")
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
        print("{}To certify the storage device:".format(INFO))
        if self._runtime >= self.__min_runtime:
            print("{0}fio needs at least {1} sec runtime per ".format(INFO,
                  self.__min_runtime) + "instance. Current setting is " +
                  "{} sec".format(self._runtime))
        else:
            print("{0}fio needs at least {1} sec runtime per ".format(WARN,
                  self.__min_runtime) + "instance. Current setting is " +
                  "{} sec".format(self._runtime))
        if self._blocksize.lower() == self.__certify_bs.lower():
            print("{0}fio needs {1} blocksize for each I/O ".format(INFO,
                  self.__certify_bs) + "unit. Current setting is " +
                  "{}".format(self._blocksize))
        else:
            print("{0}fio needs {1} blocksize for each I/O ".format(WARN,
                  self.__certify_bs) + "unit. Current setting is " +
                  "{}".format(self._blocksize))
        if self._job_per_dev == self.__certify_job:
            print("{0}fio needs {1} job for each storage device. ".format(
                  INFO, self.__certify_job) + "Current setting is " +
                  "{}".format(self._job_per_dev))
        else:
            print("{0}fio needs {1} job for each storage device. ".format(
                  WARN, self.__certify_job) + "Current setting is " +
                  "{}".format(self._job_per_dev))
        if self.iotype == self.__certify_iotp:
            print("{0}fio needs '{1}' I/O type. Current setting ".format(
                  INFO, self.__certify_iotp) + "is '{}'".format(
                  self.iotype))
        else:
            print("{0}fio needs '{1}' I/O type. Current setting ".format(
                  WARN, self.__certify_iotp) + "is '{0}{1}{2}'".format(
                  BOLDRED, self.iotype, RESETCOL))
        if self._isvalid != 'yes':
            print("{}Input argument is not suitable for ".format(ERRO) +
                  "storage readiness. However, it can do ordinary " +
                  "performance test")
            print("{}This instance will show the performance test ".format(
                  ERRO) + "result, but will not compare it with any KPI")
        print('')
        print("{}The total time consumption of running ".format(INFO) +
              "this storage readiness instance is estimated to take " +
              "{0}~{1} minutes{2}".format(PURPLE, estimated_time, RESETCOL))

        print("{}Please check above messages, especially ".format(INFO) +
              "the storage devices to be tested")
        print("Type 'yes' to continue, 'no' to stop")
        while True:
            try:
                original_choice = input('Continue? <yes|no>: ')
            except KeyboardInterrupt as e:
                sys.exit("\n{0}Hit KeyboardInterrupt. Bye!\n".format(QUIT))
            if not original_choice:
                print("{}Pressing the Enter key does not supported. ".format(
                      RED) + "Please explicitly type 'yes' or 'no'{}".format(
                      RESETCOL))
                continue
            choice = original_choice.lower()
            if choice == 'yes':
                print('')
                return 0
            elif choice == 'no':
                sys.exit("{0}Your choice is '{1}'. Bye!\n".format(QUIT,
                         original_choice))
            else:
                print("{0}Your choice is '{1}'. Type ".format(RED,
                      original_choice) + "'yes' to continue, 'no' to " +
                      "stop{}".format(RESETCOL))
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

        print("{0}Start fio instance with {1} I/O type, {2} I/O ".format(
              INFO, self.iotype, self._blocksize) + "blocksize, " +
              "{0} job(s), against {1}, runtime {2} sec, ".format(numjobs,
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

        try:
            child = Popen(shlex.split(fio_cmd), stdin=PIPE, stdout=PIPE,
                          stderr=PIPE)
            out, err = child.communicate()
        except BaseException as e:
            print("{}Tried to run fio cmd but hit exception: ".format(
                  ERRO) + "{}".format(e))
            return 1
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
              self.iotype, self._blocksize) + "against {0}, ".format(
              verb_remark) + "has completed")
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
            rc = self.run_fio_instance(str(dev), str(remark))
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
        if not self._stor_devs:
            print("{}It seems no multiple test is required".format(INFO))
            return 0
        mlt_cnt = 0
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
                rc = self.run_fio_instance(str(dev_to_test), str(devtype))
                if rc != 0:
                    print("{0}Failed to run test against all {1} ".format(ERRO,
                          devtype) + "storage devices")
                    return rc
                mlt_cnt += 1

        if mlt_cnt > 0:
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
            print("{0}{1} I/O type does not supported currently".format(
                  ERRO, self.iotype))
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
                print("{}Tried to extract drop_ios but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
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
                perf_kv[name]['iops']['mean'] = float("{:.2f}".format(
                                                iops_mean))
                perf_kv[name]['iops']['stddev'] = float("{:.2f}".format(
                                                  iops_stddev))
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
                print("{}Tried to extract latency numbers but ".format(ERRO) +
                      "hit KeyError: {}".format(e))
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
                    print("{}Tried to extract BW numbers but ".format(ERRO) +
                          "hit KeyError: {}".format(e))
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
            print("{}Failed to extract performance numbers ".format(ERRO) +
                  "from fio output file in {}".format(self.logdir))
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
            #print("{0}It seems no multiple test has been run\n".format(INFO))
            return 0

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
                print("{}Tried to extract drop_ios but hit ".format(ERRO) +
                      "KeyError: {}".format(e))
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
                perf_kv[name]['iops']['mean'] = float("{:.2f}".format(
                                                iops_mean))
                perf_kv[name]['iops']['stddev'] = float("{:.2f}".format(
                                                  iops_stddev))
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
                print("{}Tried to extract latency numbers but ".format(ERRO) +
                      "hit KeyError: {}".format(e))
                return 1
            try:
                perf_kv[name]['clat'] = {}
                perf_kv[name]['clat']['min'] = ns_to_ms(clat_min)
                perf_kv[name]['clat']['max'] = ns_to_ms(clat_max)
                perf_kv[name]['clat']['mean'] = ns_to_ms(clat_mean)
                perf_kv[name]['clat']['stddev'] = ns_to_ms(clat_stddev)
            except KeyError as e:
                print("{}Tried to save latency numbers but ".format(ERRO) +
                      "hit KeyError: {}".format(e))
                return 1
            if self._blocksize in ['1m', '2m']:
                # Bandwidth
                try:
                    bw_min = json_obj['jobs'][0][rwstr]['bw_min']
                    bw_mean = json_obj['jobs'][0][rwstr]['bw_mean']
                except KeyError as e:
                    print("{}Tried to extract BW numbers but ".format(ERRO) +
                          "hit KeyError: {}".format(e))
                    return 1
                try:
                    perf_kv[name]['bw'] = {}
                    perf_kv[name]['bw']['min'] = \
                        "{:.2f} MiB/s".format(KiB_to_MiB(bw_min))
                    perf_kv[name]['bw']['mean'] = \
                        "{:.2f} MiB/s".format(KiB_to_MiB(bw_mean))
                except BaseException as e:
                    print("{}Tried to save BW numbers but hit ".format(ERRO) +
                          "KeyError: {}".format(e))
                    return 1

        if not perf_kv:
            print("{}Failed to extract performance numbers ".format(ERRO) +
                  "from fio output file in {}".format(self.logdir))
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
                print("{0}{1} has {2} drop I/O(s) which is over the ".format(
                      ERRO, devtype, drop_ios) + "required {} ".format(
                      drop_ios_kpi) + "drop I/O KPI of {}".format(devtype))
                err_cnt += 1
            else:
                print("{0}{1} has {2} drop I/O(s) which meets the ".format(INFO,
                      devtype, drop_ios) + "required {} ".format(drop_ios_kpi) +
                      "drop I/O KPI of {}".format(devtype))
            min_iops /= devnum
            min_iops = float("{:.2f}".format(min_iops))
            if min_iops < min_iops_kpi:
                print("{0}{1} has {2} average minimum IOPS which is ".format(
                      ERRO, devtype, min_iops) + "below the required " +
                      "{0} minimum IOPS KPI of {1}".format(min_iops_kpi,
                      devtype))
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
            print("{}No performance data for single storage device".format(ERRO))
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
        if not self._mult_perf:
            #print("{} No performance data for multiple test".format(INFO))
            return 0

        for key, val in self._mult_perf.items():
            try:
                drop_ios = val['drop_ios']
                min_iops = val['iops']['min']
                mean_iops = val['iops']['mean']
                max_clat = val['clat']['max']
                mean_clat = val['clat']['mean']
            except KeyError as e:
                print("{0}Tried to get performance number of {1} ".format(ERRO,
                      key) + "but hit KeyError: {}".format(e))
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

        print("{}Define difference percentage as 100 * (max - min) ".format(INFO) +
              "/ max")
        print("{}Check if difference percentage of IOPS and latency ".format(INFO) +
              "meets the KPI")
        print('')
        err_cnt = 0
        for devtype in ['HDD', 'SSD', 'NVME']:
            try:
                devs = self._stor_devs[devtype]
            except KeyError as e:
                print("{}Tried to extract certain type of device ".format(ERRO) +
                      "from {0} but hit KeyError: {1}".format(self._stor_devs, e))
                return 1
            dev_len = len(devs)
            if dev_len < 1:
                continue
            if dev_len == 1:
                print("{0}{1} device number is not enough to do ".format(INFO,
                      devtype) + "difference percentage checking")
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
                    print("{0}Tried to extract mean numbers of {1} ".format(ERRO,
                          name) + "but hit KeyError: {}".format(e))
                    return 1
                mean_iopses.append(mean_iops)
                mean_clats.append(mean_clat)

            if len(mean_iopses) != dev_len:
                print("{0}Length of mean IOPS list of {1} is ".format(ERRO,
                      devtype) + "incorrect")
                print('')
                err_cnt += 1
                continue
            if len(mean_clats) != dev_len:
                print("{0}Length of mean latency list of {1} is ".format(ERRO,
                      devtype) + "incorrect")
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
                print("{0}All {1}s have {2}% difference of IOPS ".format(INFO,
                      devtype, iops_diff_pct) + "which is over required " +
                      "{}% maximum ".format(diff_pct_kpi) + "difference " +
                      "percentage KPI")
                err_cnt += 1
            else:
                print("{0}All {1}s have {2}% difference of IOPS ".format(INFO,
                      devtype, iops_diff_pct) + "which meets required " +
                      "{}% maximum ".format(diff_pct_kpi) + "difference " +
                      "percentage KPI")
            if clat_diff_pct > diff_pct_kpi:
                print("{0}All {1}s have {2}% difference of latency ".format(
                      INFO, devtype, clat_diff_pct) + "which is over " +
                      "required {}% maximum ".format(diff_pct_kpi) +
                      "difference percentage KPI")
                err_cnt += 1
            else:
                print("{0}All {1}s have {2}% difference of latency ".format(
                      INFO, devtype, clat_diff_pct) + "which meets " +
                      "required {}% maximum ".format(diff_pct_kpi) +
                      "difference percentage KPI")
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
                print("{}All types of storage devices passed the ".format(INFO) +
                      "KPI check")
            else:
                kpi_chk_err_cnt += 1
                print("{}Not all types of storage devices passed ".format(INFO) +
                      "the KPI check")
            print('')
            if kpi_chk_err_cnt == 0:
                print("{}Storage device of this host is ready to ".format(INFO) +
                      "run the next procedure\n")
                return 0
            else:
                print("{}*NOT* all storage devices passed the KPI ".format(ERRO) +
                      "check. This host *CANNOT* be used by IBM Storage Scale\n")
                return 1
        else:
            err_cnt = 0
            sing_rc = self.show_single_dev_result_if_invalid()
            err_cnt += sing_rc
            mult_rc = self.show_multiple_dev_results_if_invalid()
            err_cnt += mult_rc
            if err_cnt == 0:
                print("{}Storage device performance of this host ".format(ERRO) +
                      "has been tested. But this test instance is *invalid*")
            else:
                print("{}Storage device of this host did not look ".format(ERRO) +
                      "good. This host *CANNOT* be used by IBM Storage Scale\n")
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
    sr = StorageReadiness(arg_kv)

    rc = check_root_user()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    # fio can be installed from resouce code or rpm package
    rc = is_fio_available()
    if rc != 0:
        sys.exit("{0}fio benchmark should be available for ".format(QUIT) +
                 "storage readiness test\n")
    print('')

    rc = sr.initialize_storage_devices()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))
    rc = sr.initialize_KPIs()
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    time_cons = sr.estimate_time_consumption()
    if time_cons < 0:
        sys.exit("{}Bye!\n".format(QUIT))

    rc = sr.check_arguments(time_cons)
    if rc != 0:
        sys.exit("{}Bye!\n".format(QUIT))

    if sr.iotype == 'randwrite':
        show_write_warning()

    # Create LOG directory
    try:
        os.makedirs(sr.logdir)
    except BaseException as e:
        sys.exit("{0}Tried to create {1} but hit exception: {2}\n".format(QUIT,
                 sr.logdir, e))

    rc = sr.run_single_dev_tests()
    if rc != 0:
        sys.exit("{}Failed to run test against single storage device\n".format(
                 QUIT))

    rc = sr.run_multilpe_dev_tests()
    if rc != 0:
        sys.exit("{}Failed to run test against multiple storage ".format(QUIT) +
                 "devices\n")

    rc = sr.extract_single_dev_result()
    if rc != 0:
        sys.exit("{}Failed to extract result for single storage ".format(QUIT) +
                 "device\n")

    rc = sr.extract_mult_dev_result()
    if rc != 0:
        sys.exit("{0}Failed to extract result for multiple storage ".format(
                 QUIT) + "devices\n")

    return sr.summarize_test_results()


if __name__ == '__main__':
    sys.exit(main())
