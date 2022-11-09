#!/usr/bin/python
import json
import os
import sys
import stat
import datetime
import platform
import time
import argparse
from math import ceil
import subprocess


# This script version, independent from the JSON versions
NOPEUS_VERSION = "1.10"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

try:
    raw_input      # Python 2
    PYTHON3 = False
except NameError:  # Python 3
    raw_input = input
    PYTHON3 = True

if PYTHON3:
    try:
        import distro
    except ModuleNotFoundError:
        sys.exit(RED + "QUIT: " + NOCOLOR + "python3-distro is missing. Please install it.\n")
else:
    import commands


# KPI + runtime acceptance values. This is sized for 128k randread
FIO_RUNTIME = int(300)  # Acceptance value should be this or higher
MAX_PCT_DIFF = 10  # We allow up to 10% difference on drives of same type
MIN_IOPS_NVME = float(10000)
MIN_IOPS_SSD = float(800)
MIN_IOPS_HDD = float(55)
MEAN_IOPS_NVME = float(15000)
MEAN_IOPS_SSD = float(1200)
MEAN_IOPS_HDD = float(110)
MAX_LATENCY_NVME = float(20)  # msec
MAX_LATENCY_SSD = float(100)  # msec
MAX_LATENCY_HDD = float(1500)  # msec
MEAN_LATENCY_NVME = float(1.5)  # msec
MEAN_LATENCY_SSD = float(20.0)  # msec
MEAN_LATENCY_HDD = float(150.0)  # msec

# GITHUB URL
GIT_URL = "https://github.com/IBM/SpectrumScaleTools"

# devnull redirect destination
DEVNULL = open(os.devnull, 'w')


def load_json(json_file_str):
    # Loads  JSON into a dictionary or quits the program if it cannot. Future
    # might add a try to donwload the JSON if not available before quitting
    try:
        with open(json_file_str, "r") as json_file:
            json_variable = json.load(json_file)
            return json_variable
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot open JSON file: " + json_file_str)


def json_file_loads(json_file_str):
    # We try to load the JSON and return the success of failure
    try:
        with open(json_file_str, "r") as json_file_test:
            json_variable = json.load(json_file_test)
            json_file_test.close()
            json_loads = True
    except Exception:
        json_loads = False
    return json_loads


def get_json_versions(
                    os_dictionary,
                    packages_dictionary):
    # Gets the versions of the json files into a dictionary
    json_version = {}

    # Lets see if we can load version, if not quit
    try:
        json_version['supported_OS'] = os_dictionary['json_version']
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot load version from supported OS JSON")
    try:
        json_version['packages'] = packages_dictionary['json_version']
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot load version from packages JSON")
    # If we made it this far lets return the dictionary. This was being stored
    # in its own file before
    return json_version


def parse_arguments():
    valid_test = True
    parser = argparse.ArgumentParser()
    # We include number of runs and KPI as optional arguments
    parser.add_argument(
        '-b',
        '--block-sizes',
        action='store',
        dest='block_sizes',
        help='Block size for tests. ' +
        'The default and value to certify the environment is 128k. ' +
        'You can pick one from the following: 4k 128k 256k 512k 1024k',
        metavar='BS_CSV',
        type=str,
        default="128k")

    parser.add_argument(
        '--guess-drives',
        action='store_true',
        dest='guess_drives',
        help='It guesses the drives to test and adds them to the ' +
        'drives.json file overwritting its content. You should then ' +
        'manually review the file content before running the tool again',
        default=False)

    parser.add_argument(
        '--i-want-to-lose-my-data',
        action='store_true',
        dest='write_test',
        help='It makes the test a write test instead of read. This will ' +
        'delete the data that is on the drives. So if you ' +
        'care about the keeping the data on the drives you really should not ' +
        'run with this parameter. Running with this paramenter will delete all data ' +
        'on the drives',
        default=False)

    parser.add_argument(
        '-t',
        '--time-per-test',
        action='store',
        dest='fio_runtime',
        help='The number of seconds to run each test. ' +
        'The value has to be at least 30 seconds.' +
        'The minimum required value for certification is ' +
        str(FIO_RUNTIME),
        metavar='FIO_RUNTIME',
        type=int,
        default=int(FIO_RUNTIME))

    parser.add_argument(
        '--rpm_check_disabled',
        action='store_true',
        dest='no_rpm_check',
        help='Disables the RPM prerequisites check. Use only if you are ' +
        'sure all required software is installed and no RPM were used ' +
        'to install the required prerequisites. Otherwise this tool will fail',
        default=False)

    parser.add_argument('-v', '--version', action='version',
                        version='NOPEUS ' + NOPEUS_VERSION)
    args = parser.parse_args()
    if args.fio_runtime < 30:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "FIO runtime cannot be less than 30 seconds\n")
    if args.fio_runtime < FIO_RUNTIME:
        valid_test = False

    # Lets check that BS_CSV is CSV format AND that has the values we accept
    bs_list = []
    valid_bs = ["4k", "128k", "256k", "512k", "1024k"]
    try:
        block_zizes_raw = args.block_sizes
        block_sizes = block_zizes_raw.split(",")
        for block_size in block_sizes:
            if block_size in valid_bs:
                bs_list.append(block_size)
            else:
                sys.exit(RED + "QUIT: " + NOCOLOR +
                         "block sizes parameter contains invalid value[s]")        
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "block sizes parameter is not on CSV format")
    # For the time being we only accept ONE block size for the test, enforce it
    if len(bs_list) > 1:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "block sizes parameter only allows one value at this time")
    # KPIs are sized for randread 128k so we mark valid test OK for those only
    if "128k" not in bs_list:
        valid_test = False

    patterns_list = []
    #valid_patterns = ["randread", "randwrite"]
    if args.write_test:
        patterns_list.append("randwrite")
    else:
        patterns_list.append("randread")

    return (valid_test, bs_list, patterns_list, args.guess_drives, args.write_test, args.fio_runtime, args.no_rpm_check)


def rpm_is_installed(rpm_package):
    # returns the RC of rpm -q rpm_package or quits if it cannot run rpm
    try:
        return_code = subprocess.call(
            ['rpm', '-q', rpm_package], stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR + "cannot run rpm\n")
    return return_code


def packages_check(packages_dictionary):

    # Checks if packages from JSON are installed or not based on the input
    # data ont eh JSON
    errors = 0
    print(GREEN + "INFO: " + NOCOLOR + "checking packages install status")
    for package in packages_dictionary.keys():
        if package != "json_version":
            current_package_rc = rpm_is_installed(package)
            expected_package_rc = packages_dictionary[package]
            if current_package_rc == expected_package_rc:
                print(
                    GREEN +
                    "OK: " +
                    NOCOLOR +
                    "installation status of " +
                    package +
                    " is as expected")
            else:
                print(
                    YELLOW +
                    "WARNING: " +
                    NOCOLOR +
                    "installation status of " +
                    package +
                    " is *NOT* as expected")
                errors = errors + 1
    return(errors)


def check_root_user():
    effective_uid = os.getuid()
    if effective_uid == 0:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "the tool is being run as root")
    else:
        sys.exit(RED +
                 "QUIT: " +
                 NOCOLOR +
                 "this tool needs to be run as root\n")

def check_permission_files():
    #Check executable bits and read bits for files
    readable_files=["packages.json", "supported_OS.json"]
    executable_files=[]

    read_error = False
    for file in readable_files:
        if not os.access(file,os.R_OK):
            read_error = True
            print(RED +
                  "ERROR: " +
                  NOCOLOR +
                  "cannot read file " +
                  str(file) +
                  ". Have the POSIX ACL been changed?")
    exec_error = False
    for file in executable_files:
        if not os.access(file,os.X_OK):
            exec_error = True
            print(RED +
                  "ERROR: " +
                  NOCOLOR +
                  "cannot execute file " +
                  str(file) +
                  ". Have the POSIX ACL been changed?")

    if read_error or exec_error:
        fatal_error = True
    else:
        fatal_error = False
    return fatal_error


def check_drives_json(drives_dictionary):
    errors = 0
    print(GREEN + "INFO: " + NOCOLOR + "checking drives")
    # Lets check we have HDD, SSD or NVME on the entries
    for drive in drives_dictionary.keys():
        if drives_dictionary[drive].upper() == "HDD" or drives_dictionary[drive].upper() == "SSD" or drives_dictionary[drive].upper() == "NVME":
            print(GREEN + "INFO: " + NOCOLOR + drive + " drive in the JSON file seems to be correctly populated")
        else:
            print(RED + "ERROR: " + NOCOLOR + drive + " drive in the JSON file seems to be wrongly populated")
            errors = errors + 1
    if errors > 0:
        sys.exit(RED + "ERROR: " + NOCOLOR + "please check the drives JSON and check the README or GitHub repository for help\n")
    number_of_drives = len(drives_dictionary)
    if number_of_drives == 0:
        sys.exit(RED + "ERROR: " + NOCOLOR + "there are no drives defined for testing\n")


def try_guess_drives():
    #We guess the drives and write to drives.json file, then exit
    #Guess
    guess_boot_drive_command = "df -l |grep /boot |grep -v /boot/ | awk '($1~/dev/){print $1}' | tr -d '[0-9]' | cut -c6-"
    boot_drive = subprocess.getoutput(guess_boot_drive_command)
    guess_command = "lsblk -d -o name,rota --json"
    test_drives = subprocess.getoutput(guess_command)
    lsblk_dict = json.loads(test_drives)
    blockdevices_list = lsblk_dict["blockdevices"]

    #Lets parse the output and add it to dict
    drives_dictionary = {}
    for drives in blockdevices_list:
        if drives['name'] == boot_drive:
            continue
        if drives['rota'] == '1' and ('sd' in drives['name']):
            drives_dictionary.update({drives['name']: "HDD"})
        elif ('nvme' in drives['name']):
            drives_dictionary.update({drives['name']: "NVME"})
        elif ('sd' in drives['name']):
            drives_dictionary.update({drives['name']: "SSD"})

    return drives_dictionary


def write_json_file_from_dictionary(hosts_dictionary, json_file_str):
    # We are going to generate or overwrite the hosts JSON file
    try:
        with open(json_file_str, "w") as json_file:
            json.dump(hosts_dictionary, json_file)
            print(GREEN + "OK: " + NOCOLOR + "JSON file: " + json_file_str +
                  " has been [over]written")
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot write JSON file: " + json_file_str)


def print_drives(drives_dictionary):
    #print and ask for continue from end user
    if len(drives_dictionary) > 0:
        print("")
        print("We are going to test the following drives")
        print("")
        for drive in drives_dictionary.keys():
            print("\tDrive: " + str(drive) + " as " + str(drives_dictionary[drive]))
    print("")


def check_drive_exists(drives_dictionary):
    #SOme checks to see if real devices
    print(GREEN + "INFO: " + NOCOLOR + "checking devices status")
    errors = 0
    for drive in drives_dictionary.keys():
        full_path_drive = "/dev/" + drive
        try:
            stat.S_ISBLK(os.stat(full_path_drive).st_mode)
            is_there = True
        except BaseException:
            is_there = False
        if is_there:
            print(
                GREEN +
                "OK: " +
                NOCOLOR +
                drive +
                " defined as " +
                drives_dictionary[drive] +
                " is a block device")
        else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                drive +
                " defined as " +
                drives_dictionary[drive] +
                " is not a block device")
            errors = errors + 1
    if errors > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR + "please check drives definition\n")

def check_distribution():
    # Decide if this is a redhat or a CentOS. We only checking the running
    # node, that might be a problem
    if PYTHON3:
        what_dist = distro.linux_distribution()[0].lower()
    else:
        what_dist = platform.dist()[0].lower()
    if what_dist == "redhat" or "centos" or "centos linux" or "fedora":
        return what_dist
    else:  # everything esle we fail
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "this only run on RedHat at this moment")


def check_os_redhat(os_dictionary):
    redhat8 = False
    # Check redhat-release vs dictionary list
    if PYTHON3:
        redhat_distribution = distro.linux_distribution()
    else:
        redhat_distribution = platform.linux_distribution()
    redhat_distribution_str = redhat_distribution[0] + \
        " " + redhat_distribution[1]
    error_message = RED + "QUIT: " + NOCOLOR + " " + \
        redhat_distribution_str + " is not a supported OS for this tool\n"
    try:
        if os_dictionary[redhat_distribution_str] == 'OK':
            #print(GREEN + "OK: " + NOCOLOR + redhat_distribution_str +
            #      " is a supported OS for this tool")
            #print("")
            if redhat_distribution[1] == "8.0" or "8.1":
                redhat8 = True
        else:
            sys.exit(error_message)
    except Exception as e:
        sys.exit(error_message)
        print("")
    return redhat8


def run_tests(fio_runtime, drives_dictionary, log_dir_timestamp, bs_list, patterns_list):
    #Lets define a basic run then interate, only reads!
    for pattern in patterns_list:
        for blocksize in bs_list:
            for device in drives_dictionary.keys():
                print(GREEN + "INFO: " + NOCOLOR + "Going to start test " + str(pattern) + " with blocksize of " + str(blocksize) + " on device " + str(device) + " please be patient")
                fio_command = "fio --minimal --invalidate=1 --ramp_time=10 --iodepth=16 --ioengine=libaio --time_based --direct=1 --stonewall --io_size=268435456 --offset=4802187264 --runtime="+str(fio_runtime)+" --bs="+str(blocksize)+" --rw="+str(pattern)+" --filename="+str("/dev/"+device)+" --name="+str(device+"_"+pattern+"_"+blocksize)+" --output-format=json --output="+str("./log/"+log_dir_timestamp+"/"+device+"_"+pattern+"_"+blocksize+".json")
                #print (fio_command)
                fio_command_list = fio_command.split()
                rc = subprocess.call(fio_command_list)
                if rc != 0:
                    sys.exit(RED + "ERROR: " + NOCOLOR + " " + str(fio_command) + " command return a non zero return code\n")
                print("")  # To not overwrite last output line from FIO
                print(GREEN + "INFO: " + NOCOLOR + "Completed test " + str(pattern) + " with blocksize of " + str(blocksize) + " on device " + str(device))
    print(GREEN + "INFO: " + NOCOLOR + "All single drive tests completed")


def run_parallel_tests(fio_runtime, drives_dictionary, log_dir_timestamp, bs_list, patterns_list):
    HDD_drives = []
    SSD_drives = []
    NVME_drives = []
    parallel_tests = []
    for device in drives_dictionary.keys():
        if drives_dictionary[device] == "HDD":
            HDD_drives.append(device)
        elif drives_dictionary[device] == "SSD":
            SSD_drives.append(device)
        elif drives_dictionary[device] == "NVME":
            NVME_drives.append(device)
    if len(HDD_drives) > 1:
        device_long_all = ""
        parallel_tests.append("HDD")
        for device_short in HDD_drives:
            device_long_all = device_long_all + "/dev/" + device_short + ":"
        parallel_run(fio_runtime, device_long_all, "HDD", log_dir_timestamp, bs_list, patterns_list)
    if len(SSD_drives) > 1:
        device_long_all = ""
        parallel_tests.append("SSD")
        for device_short in SSD_drives:
            device_long_all = device_long_all + "/dev/" + device_short + ":"
        parallel_run(fio_runtime, device_long_all, "SSD", log_dir_timestamp, bs_list, patterns_list)
    if len(NVME_drives) > 1:
        device_long_all = ""
        parallel_tests.append("NVME")
        for device_short in NVME_drives:
            device_long_all = device_long_all + "/dev/" + device_short + ":"
        parallel_run(fio_runtime, device_long_all, "NVME", log_dir_timestamp, bs_list, patterns_list)

    print(GREEN + "INFO: " + NOCOLOR + "All parallel tests completed")
    return parallel_tests

def parallel_run(fio_runtime, device_long_all, device_type, log_dir_timestamp, bs_list, patterns_list):
    for pattern in patterns_list:
        for blocksize in bs_list:
            print(GREEN + "INFO: " + NOCOLOR + "Going to start test " + str(pattern) + " with blocksize of " + str(blocksize) + " on all devices of type " + str(device_type) + ". Please be patient")
            fio_command = "fio --minimal --invalidate=1 --ramp_time=10 --iodepth=16 --ioengine=libaio --time_based --direct=1 --stonewall --io_size=268435456 --offset=4802187264 --runtime="+str(fio_runtime)+" --bs="+str(blocksize)+" --rw="+str(pattern)+" --filename="+str(device_long_all)+" --name="+str(device_type+"_"+pattern+"_"+blocksize)+" --output-format=json --output="+str("./log/"+log_dir_timestamp+"/"+device_type+"_"+pattern+"_"+blocksize+".json")
            fio_command_list = fio_command.split()
            rc = subprocess.call(fio_command_list)
            if rc != 0:
                sys.exit(RED + "ERROR: " + NOCOLOR + " " + str(fio_command) + " command return a non zero return code\n")
            print("")  # To not overwrite last output line from FIO
            print(GREEN + "INFO: " + NOCOLOR + "Completed test " + str(pattern) + " with blocksize of " + str(blocksize) + " on devices of type " + str(device_type))


def create_local_log_dir(log_dir_timestamp):
    logdir = os.path.join(
        os.getcwd(),
        'log',
        log_dir_timestamp)
    try:
        os.makedirs(logdir)
        return logdir
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot create local directory " + logdir + "\n")


def show_write_warning():
    print("")
    print(YELLOW +
          "WARNING: " +
          NOCOLOR +
          "You have selected to perform a write test. This will delete all the data " +
          "on the drives.")
    print("")
    print("")
    run_this = raw_input("Answer 'I WANT TO LOSE MY DATA' to continue, any other text " +
                        "will terminate this program: ")
    if run_this == 'I WANT TO LOSE MY DATA':
        print("")
        return True
    else:
        print(GREEN +
            "INFO: " +
            NOCOLOR +
            "You have not accepted to lose your data. We stop at this point.")
        sys.exit("Have a nice day! Bye.\n")


def estimate_runtime(fio_runtime, drives_dictionary, bs_list, patterns_list):
    n_drives = len(drives_dictionary)
    n_patterns = len(patterns_list)
    n_blocks = len(bs_list)
    HDD_drives = []
    SSD_drives = []
    NVME_drives = []
    parallel_tests = []
    for device in drives_dictionary.keys():
        if drives_dictionary[device] == "HDD":
            HDD_drives.append(device)
        elif drives_dictionary[device] == "SSD":
            SSD_drives.append(device)
        elif drives_dictionary[device] == "NVME":
            NVME_drives.append(device)
    if len(HDD_drives) > 1:
        n_drives = n_drives + 1
    if len(SSD_drives) > 1:
        n_drives = n_drives + 1
    if len(NVME_drives) > 1:
        n_drives = n_drives + 1

    estimated_rt_fio = n_drives * n_patterns * n_blocks * fio_runtime
    estimated_ramp_time = n_drives * n_patterns * n_blocks * 10
    estimated_runtime = estimated_rt_fio + estimated_ramp_time
    estimated_runtime_minutes = int(ceil(estimated_runtime / 60.))
    return estimated_runtime_minutes


def show_header(json_version, estimated_runtime_str, fio_runtime, drives_dictionary, bs_list, patterns_list):
    # Say hello and give chance to disagree
    while True:
        print("")
        print(GREEN +
              "Welcome to NOPEUS, version " +
              str(NOPEUS_VERSION) +
              NOCOLOR)
        print("")
        print("JSON files versions:")
        print("\tsupported OS:\t\t" + json_version['supported_OS'])
        print("\tpackages: \t\t" + json_version['packages'])
        print("")
        print("Please use " + GIT_URL +
              " to get latest versions and report issues about this tool.")
        print("")
        print(
            "The purpose of NOPEUS is to obtain drive metrics, " +
            "and compare them against KPIs")
        print("")
        if fio_runtime >= FIO_RUNTIME:
            print(GREEN + "The FIO runtime per test of " + str(fio_runtime) +
                  " seconds is sufficient to certify the environment" + NOCOLOR)
        else:
            print(
                YELLOW +
                "WARNING: " +
                NOCOLOR +
                "The FIO runtime per test of " + str(fio_runtime) +
                " seconds is not sufficient to certify the environment")
        print("")
        if "128k" in bs_list:
            print(GREEN + "The FIO blocksize of 128k is valid " +
                  "to certify the environment" + NOCOLOR)
        else:
            print(
                YELLOW +
                "WARNING: " +
                NOCOLOR +
                "The FIO blocksize " +
                "is not valid to certify the environment")
        print("")
        if "randread" in patterns_list:
            print(GREEN + "The FIO patterns of randread is valid " +
                  "to certify the environment" + NOCOLOR)
        else:
            print(
                YELLOW +
                "WARNING: " +
                NOCOLOR +
                "The FIO pattern " +
                "is not valid to certify the environment")
        print("")
        print(YELLOW + "This test run estimation is " +
              estimated_runtime_str + " minutes" + NOCOLOR)
        print("")
        print(
            RED +
            "This software comes with absolutely no warranty of any kind. " +
            "Use it at your own risk" +
            NOCOLOR)
        print("")
        print(
            RED +
            "NOTE: The bandwidth and latency numbers shown in this tool " +
            "are for a very specific test. " +
            "This is not a generic storage benchmark." +
            NOCOLOR)
        print(
            RED +
            "The numbers do not reflect the numbers you would see with " +
            "Spectrum Scale and your particular workload" +
            NOCOLOR)
        print("")
        print_drives(drives_dictionary)
        run_this = raw_input("Do you want to continue? (y/n): ")
        if run_this.lower() == 'y':
            break
        if run_this.lower() == 'n':
            print
            sys.exit("Have a nice day! Bye.\n")
    print("")


def load_fio_tests(drives_dictionary, logdir, bs_list, patterns_list, write_accepted):
    fio_json_test_key_l = []
    fio_iops_d = {}
    fio_iops_min_d = {}
    fio_iops_mean_d = {}
    fio_iops_stddev_d = {}
    fio_iops_drop_d = {}
    fio_lat_min_d = {}
    fio_lat_mean_d = {}
    fio_lat_stddev_d = {}
    fio_lat_max_d = {}

    for pattern in patterns_list:
        if write_accepted:
            pattern_key = "write"
        else:
            pattern_key = "read"
        for blocksize in bs_list:
            for device in drives_dictionary.keys():
                test_key = device + "_" + pattern + "_" + blocksize
                fio_json = str(logdir+ "/" + test_key + ".json")
                #fio_IOPS_d[device] = fio_json[]
                test_load = load_json(fio_json)
                #IOPS
                iops = test_load["jobs"][0][pattern_key]["iops"]
                iops = "%.2f" % iops
                iops_min = test_load["jobs"][0][pattern_key]["iops_min"]
                iops_mean = test_load["jobs"][0][pattern_key]["iops_mean"]
                iops_stddev = test_load["jobs"][0][pattern_key]["iops_stddev"]
                iops_drop = test_load["jobs"][0][pattern_key]["drop_ios"]
                fio_iops_d[test_key] = float("%.2f" % float(iops))
                fio_iops_min_d[test_key] = float(iops_min)
                fio_iops_mean_d[test_key] = float("%.2f" % float(iops_mean))
                fio_iops_stddev_d[test_key] = float("%.2f" % float(iops_stddev))
                fio_iops_drop_d[test_key] = float(iops_drop)
                #LATENCY
                lat_min = test_load["jobs"][0][pattern_key]["clat_ns"]["min"]/1000000
                lat_mean = test_load["jobs"][0][pattern_key]["clat_ns"]["mean"]/1000000
                lat_stddev = test_load["jobs"][0][pattern_key]["clat_ns"]["stddev"]/1000000
                lat_max = test_load["jobs"][0][pattern_key]["clat_ns"]["max"]/1000000
                fio_lat_min_d[test_key] = float(lat_min)
                fio_lat_mean_d[test_key] = float("%.2f" % float(lat_mean))
                fio_lat_stddev_d[test_key] = float("%.2f" % float(lat_stddev))
                fio_lat_max_d[test_key] = float(lat_max)
                #Append test_key
                fio_json_test_key_l.append(test_key)

    return (fio_json_test_key_l, fio_iops_d, fio_iops_min_d, fio_iops_mean_d,
            fio_iops_stddev_d, fio_iops_drop_d, fio_lat_min_d, fio_lat_mean_d,
            fio_lat_stddev_d, fio_lat_max_d)


def load_fio_parallel_tests(drives_dictionary, logdir, parallel_tests, bs_list, patterns_list, write_accepted):
    fio_json_test_key_l = []
    fio_iops_d = {}
    fio_iops_min_d = {}
    fio_iops_mean_d = {}
    fio_iops_stddev_d = {}
    fio_iops_drop_d = {}
    fio_lat_min_d = {}
    fio_lat_mean_d = {}
    fio_lat_stddev_d = {}
    fio_lat_max_d = {}

    for pattern in patterns_list:
        if write_accepted:
            pattern_key = "write"
        else:
            pattern_key = "read"
        for blocksize in bs_list:
            for device in parallel_tests:
                test_key = device + "_" + pattern + "_" + blocksize
                fio_json = str(logdir+ "/" + test_key + ".json")
                #fio_IOPS_d[device] = fio_json[]
                test_load = load_json(fio_json)
                #IOPS
                iops = test_load["jobs"][0][pattern_key]["iops"]
                iops = "%.2f" % iops
                iops_min = test_load["jobs"][0][pattern_key]["iops_min"]
                iops_mean = test_load["jobs"][0][pattern_key]["iops_mean"]
                iops_stddev = test_load["jobs"][0][pattern_key]["iops_stddev"]
                iops_drop = test_load["jobs"][0][pattern_key]["drop_ios"]
                fio_iops_d[test_key] = float("%.2f" % float(iops))
                fio_iops_min_d[test_key] = float(iops_min)
                fio_iops_mean_d[test_key] = float("%.2f" % float(iops_mean))
                fio_iops_stddev_d[test_key] = float("%.2f" % float(iops_stddev))
                fio_iops_drop_d[test_key] = float(iops_drop)
                #LATENCY
                lat_min = test_load["jobs"][0][pattern_key]["clat_ns"]["min"]/1000000
                lat_mean = test_load["jobs"][0][pattern_key]["clat_ns"]["mean"]/1000000
                lat_stddev = test_load["jobs"][0][pattern_key]["clat_ns"]["stddev"]/1000000
                lat_max = test_load["jobs"][0][pattern_key]["clat_ns"]["max"]/1000000
                fio_lat_min_d[test_key] = float(lat_min)
                fio_lat_mean_d[test_key] = float("%.2f" % float(lat_mean))
                fio_lat_stddev_d[test_key] = float("%.2f" % float(lat_stddev))
                fio_lat_max_d[test_key] = float(lat_max)
                #Append test_key
                fio_json_test_key_l.append(test_key)

    return (fio_json_test_key_l, fio_iops_d, fio_iops_min_d, fio_iops_mean_d,
            fio_iops_stddev_d, fio_iops_drop_d, fio_lat_min_d, fio_lat_mean_d,
            fio_lat_stddev_d, fio_lat_max_d)


def parallel_tests_print(pfio_json_test_key_l, pfio_iops_d, pfio_iops_min_d, pfio_iops_mean_d, \
    pfio_iops_stddev_d, pfio_iops_drop_d, pfio_lat_min_d, pfio_lat_mean_d, \
    pfio_lat_stddev_d, pfio_lat_max_d):
    fatal_error = 0
    for test in pfio_iops_mean_d.keys():
        print(
            GREEN +
            "INFO: " +
            NOCOLOR +
            "test " +
            test +
            " has mean IOPS of " +
            str(pfio_iops_mean_d[test])
        )
    for test in pfio_lat_mean_d.keys():
        print(
            GREEN +
            "INFO: " +
            NOCOLOR +
            "test " +
            test +
            " has mean latency of " +
            str(pfio_lat_mean_d[test]) +
            " msec"
        )
    for test in pfio_iops_drop_d.keys():
        if pfio_iops_drop_d[test] == 0:
            print(
                GREEN +
                "INFO: " +
                NOCOLOR +
                "test " +
                test +
                " has IOPS drop of " +
                str(pfio_iops_drop_d[test])
            )
        else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "test " +
                test +
                " has IOPS drop of " +
                str(pfio_iops_drop_d[test])
            )
            fatal_error = fatal_error + 1
    return fatal_error


def compare_against_kpis(drives_dictionary, fio_json_test_key_l,
                         fio_iops_min_d, fio_iops_drop_d, fio_lat_max_d,
                         fio_iops_mean_d, fio_lat_mean_d):
    errors = 0
    #Each drive to the KPI type
    for drive in drives_dictionary.keys():
        for test_key in fio_json_test_key_l:
            if drive in test_key:
                if fio_iops_drop_d[test_key] == 0:
                    print(
                        GREEN +
                        "OK: " +
                        NOCOLOR +
                        "drive " +
                        drive +
                        " with IO drop[s] of " +
                        str(fio_iops_drop_d[test_key]) +
                        " passes the IO drops KPI of 0" +
                        " for test " +
                        str(test_key))
                else:
                    print(
                        RED +
                        "ERROR: " +
                        NOCOLOR +
                        "drive " +
                        drive +
                        " with IO drop[s] of " +
                        str(fio_iops_drop_d[test_key]) +
                        " does not pass the IO drops KPI of 0" +
                        " for test " +
                        str(test_key))

                if drives_dictionary[drive].upper() == "HDD":
                    if fio_iops_min_d[test_key] >= MIN_IOPS_HDD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " passes the HDD IOPS KPI of " +
                            str(MIN_IOPS_HDD) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " does not pass the HDD IOPS KPI of " +
                            str(MIN_IOPS_HDD) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_max_d[test_key] <= MAX_LATENCY_HDD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec passes the HDD latency KPI of " +
                            str(MAX_LATENCY_HDD) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec does not pass the HDD latency KPI of " +
                            str(MAX_LATENCY_HDD) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_iops_mean_d[test_key] >= MEAN_IOPS_HDD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " passes the HDD IOPS KPI of " +
                            str(MEAN_IOPS_HDD) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " does not pass the HDD IOPS KPI of " +
                            str(MEAN_IOPS_HDD) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_mean_d[test_key] <= MEAN_LATENCY_HDD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec passes the HDD latency KPI of " +
                            str(MEAN_LATENCY_HDD) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec does not pass the HDD latency KPI of " +
                            str(MEAN_LATENCY_HDD) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1

                if drives_dictionary[drive].upper() == "SSD":
                    if fio_iops_min_d[test_key] >= MIN_IOPS_SSD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " passes the SSD IOPS KPI of " +
                            str(MIN_IOPS_SSD) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " does not pass the SSD IOPS KPI of " +
                            str(MIN_IOPS_SSD) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_max_d[test_key] <= MAX_LATENCY_SSD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec passes the SSD latency KPI of " +
                            str(MAX_LATENCY_SSD) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec does not pass the SSD latency KPI of " +
                            str(MAX_LATENCY_SSD) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_iops_mean_d[test_key] >= MEAN_IOPS_SSD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " passes the SSD IOPS KPI of " +
                            str(MEAN_IOPS_SSD) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " does not pass the SSD IOPS KPI of " +
                            str(MEAN_IOPS_SSD) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_mean_d[test_key] <= MEAN_LATENCY_SSD:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec passes the SSD latency KPI of " +
                            str(MEAN_LATENCY_SSD) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec does not pass the SSD latency KPI of " +
                            str(MEAN_LATENCY_SSD) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1

                if drives_dictionary[drive].upper() == "NVME":
                    if fio_iops_min_d[test_key] >= MIN_IOPS_NVME:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " passes the NVME IOPS KPI of " +
                            str(MIN_IOPS_NVME) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with minimum IOPS of " +
                            str(fio_iops_min_d[test_key]) +
                            " does not pass the NVME IOPS KPI of " +
                            str(MIN_IOPS_NVME) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_max_d[test_key] <= MAX_LATENCY_NVME:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec passes the NVME latency KPI of " +
                            str(MAX_LATENCY_NVME) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with maximum latency of " +
                            str(fio_lat_max_d[test_key]) +
                            " msec does not pass the NVME latency KPI of " +
                            str(MAX_LATENCY_NVME) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_iops_mean_d[test_key] >= MEAN_IOPS_NVME:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " passes the NVME IOPS KPI of " +
                            str(MEAN_IOPS_NVME) +
                            " for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean IOPS of " +
                            str(fio_iops_mean_d[test_key]) +
                            " does not pass the NVME IOPS KPI of " +
                            str(MEAN_IOPS_NVME) +
                            " for test " +
                            str(test_key))
                        errors = errors + 1

                    if fio_lat_mean_d[test_key] <= MEAN_LATENCY_NVME:
                        print(
                            GREEN +
                            "OK: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec passes the NVME latency KPI of " +
                            str(MEAN_LATENCY_NVME) +
                            " msec for test " +
                            str(test_key))
                    else:
                        print(
                            RED +
                            "ERROR: " +
                            NOCOLOR +
                            "drive " +
                            drive +
                            " with mean latency of " +
                            str(fio_lat_mean_d[test_key]) +
                            " msec does not pass the NVME latency KPI of " +
                            str(MEAN_LATENCY_NVME) +
                            " msec for test " +
                            str(test_key))
                        errors = errors + 1
    return errors


def pct_diff_list(list):
    #Expect floats
    if len(list) < 2:
        return 0
    try:
        pc_diff = abs(min(list) * 100 / (max(list)) - 100)
    except BaseException:
        sys.exit(
            RED +
            "QUIT: " +
            NOCOLOR +
            "cannot calculate percentage\n")
    pc_diff = float("%.2f" % float(pc_diff))
    return pc_diff


def compare_peers(drives_dictionary,
                  fio_json_test_key_l,
                  fio_iops_mean_d,
                  fio_lat_mean_d,
                  drive_type):
    # We compare mean against all peers to see a % difference
    list_iops = []
    list_lat = []
    errors = 0
    for drive in drives_dictionary.keys():
        for test_key in fio_json_test_key_l:
            if drive in test_key:
                if drives_dictionary[drive].upper() == drive_type:
                    list_iops.append(fio_iops_mean_d[test_key])
                    list_lat.append(fio_lat_mean_d[test_key])

    if len(list_iops) == 0:
        print(
            GREEN +
            "INFO: " +
            NOCOLOR +
            "drive type " +
            str(drive_type) +
            " was not tested, so no percentage difference applies for test " +
            str(test_key))
        return 0

    if len(list_iops) == 1:
        print(
            GREEN +
            "INFO: " +
            NOCOLOR +
            "drive type " +
            str(drive_type) +
            " has only one drive, so no percentage difference applies for test " +
            str(test_key))
        return 0

    iops_pct_diff = pct_diff_list(list_iops)
    lat_pct_diff = pct_diff_list(list_lat)
    if iops_pct_diff <= MAX_PCT_DIFF:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "drive type " +
            str(drive_type) +
            " has IOPS percentage difference of " +
            str(iops_pct_diff) +
            "% which passes the KPI of " +
            str(MAX_PCT_DIFF) +
            "% for IOPS difference for same drive type for test " +
            str(test_key))
    else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "drive type " +
                str(drive_type) +
                " has IOPS percentage difference of " +
                str(iops_pct_diff) +
                "% which does not pass the KPI of " +
                str(MAX_PCT_DIFF) +
                "% for IOPS difference for same drive type for test " +
                str(test_key))
            errors = errors + 1

    if lat_pct_diff <= MAX_PCT_DIFF:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "drive type " +
            str(drive_type) +
            " has latency percentage difference of " +
            str(lat_pct_diff) +
            "% which passes the KPI of " +
            str(MAX_PCT_DIFF) +
            "% for latency difference for same drive type for test " +
            str(test_key))
    else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "drive type " +
                str(drive_type) +
                " has latency percentage difference of " +
                str(lat_pct_diff) +
                "% which does not pass the KPI of " +
                str(MAX_PCT_DIFF) +
                "% for latency difference for same drive type for test " +
                str(test_key))
            errors = errors + 1
    return errors


def print_summary(valid_test, kpi_errors_int):
    print("")
    print("Summary of this run:")
    if valid_test:
        if kpi_errors_int == 0:
            print(GREEN +
                  "\tSUCCESS: " +
                  NOCOLOR +
                  "All drives fulfill the KPIs. You can continue with the next steps")
        else:
            print(RED +
                  "\tFAILURE: " +
                  NOCOLOR +
                  "All drives do not fulfill the KPIs. You *cannot* continue with the next steps")
    else:
        if kpi_errors_int == 0:
            print(YELLOW +
                  "\tFAILURE: " +
                  NOCOLOR +
                  "All drives fulfill the KPIs. However you *cannot* continue with the next steps")
        else:
            print(RED +
                  "\tFAILURE: " +
                  NOCOLOR +
                  "All drives do not fulfill the KPIs. You *cannot* continue with the next steps")
        print(RED +
              "\tERROR: " +
              NOCOLOR +
              "The settings of this test run do not qualify as a valid run to check their KPIs. You *cannot* continue with the next steps")

    print("")

def main():
    # Check files permissions
    fatal_error = check_permission_files()
    if fatal_error:
        sys.exit(RED + "QUIT: " + NOCOLOR + "there are files with "+
                 "unexpected permissions or non existing\n")

    # Parsing input
    valid_test, bs_list, patterns_list, guess_drives, write_test, fio_runtime, no_rpm_check = parse_arguments()

    # JSON loads
    os_dictionary = load_json("supported_OS.json")
    packages_dictionary = load_json("packages.json")
    if guess_drives and PYTHON3:
        drives_dictionary = try_guess_drives()
        #Overwrite the drives file
        write_json_file_from_dictionary(drives_dictionary, "drives.json")
    elif guess_drives and not PYTHON3:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "guess drives only works with Python 3\n")
    else:
        drives_dictionary = load_json("drives.json")
    json_version = get_json_versions(os_dictionary, packages_dictionary)

    # Check OS
    linux_distribution = check_distribution()
    if linux_distribution in ["redhat", "centos", "centos linux", "fedora", "red hat enterprise linux"]:
        redhat8 = check_os_redhat(os_dictionary)
    else:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "this is not a supported OS to run this tool\n")

    # Headers
    estimated_runtime = estimate_runtime(fio_runtime, drives_dictionary, bs_list, patterns_list)
    show_header(json_version, str(estimated_runtime), fio_runtime, drives_dictionary, bs_list, patterns_list)
    write_accepted = False
    if write_test:
        write_accepted = show_write_warning()

    # Check packages
    if no_rpm_check == False:
        packages_errors = packages_check(packages_dictionary)
        if packages_errors > 0:
            sys.exit(
                RED +
                "QUIT: " +
                NOCOLOR +
                " has missing packages that need to be installed before " +
                "running this tool. Please take a look to the README file\n")
    else:
        print(YELLOW +
              "WARNING: " +
              NOCOLOR +
              "you have disabled the RPM check, tool will fail if " +
              "prerequisites listed on the README file are not installed")

    # Check root user
    check_root_user()

    # Check drives JSON entries
    check_drives_json(drives_dictionary)

    # Check drives
    check_drive_exists(drives_dictionary)

    # Create LOG directory
    log_dir_timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    logdir = create_local_log_dir(log_dir_timestamp)

    # Run tests
    if write_accepted:
        # Second and last warning about write tests
        show_write_warning()
    run_tests(fio_runtime, drives_dictionary, log_dir_timestamp, bs_list, patterns_list)
    parallel_tests = run_parallel_tests(fio_runtime, drives_dictionary, log_dir_timestamp, bs_list, patterns_list)

    # Load results
    fio_json_test_key_l, fio_iops_d, fio_iops_min_d, fio_iops_mean_d, \
    fio_iops_stddev_d, fio_iops_drop_d, fio_lat_min_d, fio_lat_mean_d, \
    fio_lat_stddev_d, fio_lat_max_d = load_fio_tests(drives_dictionary, logdir, bs_list, patterns_list, write_accepted)

    pfio_json_test_key_l, pfio_iops_d, pfio_iops_min_d, pfio_iops_mean_d, \
    pfio_iops_stddev_d, pfio_iops_drop_d, pfio_lat_min_d, pfio_lat_mean_d, \
    pfio_lat_stddev_d, pfio_lat_max_d = load_fio_parallel_tests(drives_dictionary, logdir, parallel_tests, bs_list, patterns_list, write_accepted)

    # Compare against KPIs
    kpi_errors_int = compare_against_kpis(drives_dictionary,
                                          fio_json_test_key_l,
                                          fio_iops_min_d,
                                          fio_iops_drop_d,
                                          fio_lat_max_d,
                                          fio_iops_mean_d,
                                          fio_lat_mean_d)

    HDD_diff_errors_int = compare_peers(drives_dictionary,
                                        fio_json_test_key_l,
                                        fio_iops_mean_d,
                                        fio_lat_mean_d,
                                        "HDD")
    SSD_diff_errors_int = compare_peers(drives_dictionary,
                                        fio_json_test_key_l,
                                        fio_iops_mean_d,
                                        fio_lat_mean_d,
                                        "SSD")
    NVME_diff_errors_int = compare_peers(drives_dictionary,
                                        fio_json_test_key_l,
                                        fio_iops_mean_d,
                                        fio_lat_mean_d,
                                        "NVME")

    if (HDD_diff_errors_int + SSD_diff_errors_int + NVME_diff_errors_int) == 0:
        print(GREEN +
              "OK: " +
              NOCOLOR +
              "the difference between drives is acceptable by the KPIs")
    else:
        print(RED +
              "ERROR: " +
              NOCOLOR +
              "the difference between drives is not acceptable by the KPIs")
        kpi_errors_int = kpi_errors_int + 1

    #Parallel info, drops still give error
    parallel_errors = parallel_tests_print(pfio_json_test_key_l, pfio_iops_d, pfio_iops_min_d, pfio_iops_mean_d, \
    pfio_iops_stddev_d, pfio_iops_drop_d, pfio_lat_min_d, pfio_lat_mean_d, \
    pfio_lat_stddev_d, pfio_lat_max_d)

    if (parallel_errors) >0:
        kpi_errors_int = kpi_errors_int + 1

    # Exit protocol
    DEVNULL.close()
    print_summary(valid_test, kpi_errors_int)


if __name__ == '__main__':
    main()

