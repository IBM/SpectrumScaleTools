#!/usr/bin/python
import json
import os
import sys
import datetime
import subprocess
import platform
import argparse
import socket
import importlib
import hashlib
import re
import shlex
import logging
import multiprocessing

try:
    raw_input      # Python 2
    PYTHON3 = False
except NameError:  # Python 3
    raw_input = input
    PYTHON3 = True

if PYTHON3:
    import subprocess
else:
    import commands


# Start the clock
start_time_date = datetime.datetime.now()

# This script version, independent from the JSON versions
MOR_VERSION = "1.63"

# GIT URLs
GITREPOURL = "https://github.com/IBM/SpectrumScaleTools"
TUNED_TOOL = "ece_tuned_profile in https://github.com/IBM/SpectrumScaleTools"
STORAGE_TOOL = "ece_storage_readiness in https://github.com/IBM/SpectrumScaleTools"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

# Message labels
INFO = "[ " + GREEN + "INFO" + NOCOLOR + "  ] "
WARNING = "[ " + YELLOW + "WARN" + NOCOLOR + "  ] "
ERROR = "[ " + RED + "FATAL" + NOCOLOR + " ] "

# Get hostname for output on screen
LOCAL_HOSTNAME = platform.node().split('.', 1)[0]

# Regex patterns
SASPATT = re.compile('.*"SAS address"\s*:\s*"0x(?P<sasaddr>.*)"')
WWNPATT = re.compile('.*"WWN"\s*:\s*"(?P<wwn>.*)"')
OSVERPATT = re.compile('(?P<major>\d+)[\.](?P<minor>\d+)[\.].*')
PCIPATT = re.compile('(?P<pciaddr>[a-fA-f0-9]{2}:[a-fA-f0-9]{2}[\.][0-9])'
                     '[\ ](?P<pcival>.*)')
                     
# Next are python modules that need to be checked before import
if platform.processor() != 's390x':
    try:
        import dmidecode
    except ImportError:
        if PYTHON3:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot import dmidecode, please check python3-dmidecode" +
                " is installed")
        else:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot import dmidecode, please check python-dmidecode" +
                " is installed")
if PYTHON3:
    try:
        import distro
    except ImportError:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot import distro, please check python3-distro" +
            " is installed")

try:
    import ethtool
except ImportError:
    if PYTHON3:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot import ethtool, please check python3-ethtool is installed")
    else:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot import ethtool, please check python-ethtool is installed")


# devnull redirect destination
DEVNULL = open(os.devnull, 'w')

# Set SAS client tool: strocli64 or perccli64(Dell machine)
# Use set_sas_tool to initialize
SAS_TOOL_ALIAS = ""
SAS_TOOL = ""

# Define expected MD5 hashes of JSON input files
HW_REQUIREMENTS_MD5 = "a22d65d640888409219d70352dd7228d"
NIC_ADAPTERS_MD5 = "00412088e36bce959350caea5b490001"
PACKAGES_MD5 = "a15b08b05998d455aad792ef5d3cc811"
SAS_ADAPTERS_MD5 = "d06fe3822fabf7798403e74e2796967b"
SUPPORTED_OS_MD5 = "4153f6b62aa2ce4f4c3de4e3db422745"

# Functions
def set_logger_up(output_dir, log_file, verbose):
    if os.path.isdir(output_dir) == False:
        try:
            os.makedirs(output_dir)
        except BaseException:
            sys.exit(
                ERROR + 
                LOCAL_HOSTNAME +
                " Cannot create " + 
                output_dir
            )
    log_format = '%(asctime)s %(levelname)-4s:\t %(message)s'
    logging.basicConfig(level=logging.DEBUG,
            format=log_format,
            filename=log_file,
            filemode='w')
 
    console = logging.StreamHandler()
    if verbose:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(log_format))
    logging.getLogger('').addHandler(console)
    log = logging.getLogger("MOR")
    return log


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--FIPS',
        action='store_true',
        dest='fips',
        help='Does not run parts of the code that cannot run on FIPS systems. ' +
        'The run with this parameter is not complete and cannot be used for acceptance.',
        default=False)

    parser.add_argument(
        '--ip',
        required=True,
        action='store',
        dest='ip_address',
        help='Local IP address linked to device used for NSD',
        metavar='IPv4_ADDRESS',
        type=str,
        default="NO IP")

    parser.add_argument(
        '--path',
        action='store',
        dest='path',
        help='Path where JSON files are located. Defaults to local directory',
        metavar='PATH/',
        type=str,
        default='./')

    parser.add_argument(
        '--no-cpu-check',
        action='store_false',
        dest='cpu_check',
        help='Does not run CPU checks',
        default=True)

    parser.add_argument(
        '--no-md5-check',
        action='store_false',
        dest='md5_check',
        help='Does not check MD5 of JSON files',
        default=True)

    parser.add_argument(
        '--no-mem-check',
        action='store_false',
        dest='mem_check',
        help='Does not run memory checks',
        default=True)

    parser.add_argument(
        '--no-os-check',
        action='store_false',
        dest='os_check',
        help='Does not run OS checks',
        default=True)

    parser.add_argument(
        '--no-packages-check',
        action='store_false',
        dest='packages_ch',
        help='Does not run packages checks',
        default=True)

    parser.add_argument(
        '--no-net-check',
        action='store_false',
        dest='net_check',
        help='Does not run network checks',
        default=True)

    parser.add_argument(
        '--no-storage-check',
        action='store_false',
        dest='storage_check',
        help='Does not run storage checks',
        default=True)

    parser.add_argument(
        '--no-tuned-check',
        action='store_false',
        dest='tuned_check',
        help='Does not run tuned checks',
        default=True)

    parser.add_argument(
        '--allow-sata',
        action='store_true',
        dest='sata_on',
        help='EXPERIMENTAL: To do checks on SATA drives. Do NOT use for real checks',
        default=False)

    parser.add_argument(
        '--toolkit',
        action='store_true',
        dest='toolkit_run',
        help='To indicate is being run from Spectrum Scale install toolkit',
        default=False)

    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version='IBM Spectrum Scale Erasure Code Edition OS readiness ' +
        'version: ' + MOR_VERSION)

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        dest='is_verbose',
        help='Shows debug messages on console',
        default=False)

    args = parser.parse_args()

    return (args.fips,
            args.ip_address,
            args.path,
            args.cpu_check,
            args.md5_check,
            args.mem_check,
            args.os_check,
            args.packages_ch,
            args.storage_check,
            args.net_check,
            args.tuned_check,
            args.sata_on,
            args.toolkit_run,
            args.is_verbose)

def set_sas_tool():
    global SAS_TOOL_ALIAS
    global SAS_TOOL
    try:
        if PYTHON3:
            vendor = subprocess.getoutput(
                "dmidecode -s system-manufacturer"
            )
        else:
            vendor = commands.getoutput(
                "dmidecode -s system-manufacturer"
            )
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query system manufacturer"
            )
    if vendor is not None and vendor.startswith('Dell Inc.'):
        SAS_TOOL_ALIAS = 'perccli'
        SAS_TOOL = '/opt/MegaRAID/perccli/perccli64'
    else:
        SAS_TOOL_ALIAS = 'storcli'
        SAS_TOOL = '/opt/MegaRAID/storcli/storcli64'


    print(
        INFO +
        LOCAL_HOSTNAME + " SAS TOOL:" +
        SAS_TOOL)
    return


def load_json(json_file_str):
    # Loads  JSON into a dictionary or quits the program if it cannot.
    try:
        with open(json_file_str, "r") as json_file:
            json_dict = json.load(json_file)
            return json_dict
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot open or parse JSON file: '" +
            json_file_str +
            "'. Please check the file exists and has JSON format")


def md5_chksum(json_file_str):
    # Files are small not doing chunks
    try:
        md5_hash = (hashlib.md5(open(json_file_str, 'rb').read()).hexdigest())
        return md5_hash
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot create MD5 sum of file: " +
            json_file_str)


def md5_verify(md5_check, json_file_str, md5_hash_real, md5_hash_expected):
    # Compare expected MD5 with real one and print message if OK and message
    # plus exit if not OK
    if md5_hash_real == md5_hash_expected:
        # print(INFO + LOCAL_HOSTNAME +
        # " MD5 hash verified for " + json_file_str)
        return True
    elif md5_check:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " MD5 hash failed to verify file: " +
            json_file_str)
    else:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " MD5 hash failed to verify file: " +
            json_file_str)
        return False
        
def convert_to_bytes(size, unit):
    unit_dict = { "KB":10**3, "MB":10**6,"GB":10**9, "TB":10**12, "KiB":2**10, "MiB":2**20, "GiB":2**30, "TiB": 2**40 }
    size_in_bytes = -1
    if unit in unit_dict.keys():
        size_in_bytes = size * unit_dict[unit]
    return size_in_bytes


def show_header(moh_version, json_version, toolkit_run):
    print(
        INFO +
        LOCAL_HOSTNAME +
        " IBM Spectrum Scale Erasure Code Edition OS readiness version " +
        moh_version)
    if not toolkit_run:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " This tool comes with absolute not warranty")
        print(
            INFO +
            LOCAL_HOSTNAME +
            " Please check " + GITREPOURL + " for details")
    print(INFO + LOCAL_HOSTNAME + " JSON files versions:")
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tsupported OS:\t\t" +
        json_version['supported_OS'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tpackages: \t\t" +
        json_version['packages'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tSAS adapters:\t\t" +
        json_version['SAS_adapters'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tNIC adapters:\t\t" +
        json_version['NIC_adapters'])
    print(
        INFO +
        LOCAL_HOSTNAME +
        " \tHW requirements:\t" +
        json_version['HW_requirements'])


def rpm_is_installed(rpm_package):
    # returns the RC of rpm -q rpm_package or quits if it cannot run rpm
    try:
        return_code = subprocess.call(
            ['rpm', '-q', rpm_package], stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot run rpm")
    return return_code


def is_IP_address(ip):
    # Lets check is a full ip by counting dots
    if ip.count('.') != 3:
        return False
    try:
        socket.inet_aton(ip)
        return True
    except Exception:
        return False


def list_net_devices():
    # This works on Linux only
    # net_devices = os.listdir('/sys/class/net/')
    net_devices = ethtool.get_active_devices()
    return net_devices


def what_interface_has_ip(net_devices, ip_address):
    fatal_error = True
    for device in net_devices:
        try:
            device_ip = ethtool.get_ipaddr(str(device))
        except BaseException:
            continue
        if device_ip != ip_address:
            fatal_error = True
        else:
            fatal_error = False
            print(
                INFO +
                LOCAL_HOSTNAME +
                " the IP address " +
                ip_address +
                " is found on device " +
                device)
            return fatal_error, device
    print(
        ERROR +
        LOCAL_HOSTNAME +
        " cannot find interface with IP address " +
        ip_address)
    return fatal_error, "NONE"


def check_NIC_speed(net_interface, min_link_speed):
    fatal_error = False
    device_speed = 0
    try:
        if PYTHON3:
            ethtool_out = subprocess.getoutput(
                'ethtool ' + net_interface + ' | grep "Speed:"').split()
        else:
            ethtool_out = commands.getoutput(
                'ethtool ' + net_interface + ' | grep "Speed:"').split()
        device_speed = ''.join(ethtool_out[1].split())
        device_speed = device_speed[:-4]
        device_speed = device_speed[-6:]
        if int(device_speed) > min_link_speed:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " interface " +
                net_interface +
                " has a link of " +
                device_speed +
                " Mb/s. Which is supported to run ECE")
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " interface " +
                net_interface +
                " has a link of " +
                device_speed +
                " Mb/s. Which is not supported to run ECE")
            fatal_error = True
    except BaseException:
        fatal_error = True
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot determine link speed on " +
            net_interface +
            ". Is the link up?")
    return fatal_error, device_speed


def check_root_user():
    effective_uid = os.getuid()
    if effective_uid == 0:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " the tool is being run as root")
    else:
        sys.exit(ERROR +
                 LOCAL_HOSTNAME +
                 " this tool needs to be run as root\n")


def packages_check(packages_dictionary):

    # Checks if packages from JSON are installed or not based on the input
    # data ont eh JSON
    errors = 0
    print(INFO + LOCAL_HOSTNAME + " checking packages install status")
    for package in packages_dictionary.keys():
        if platform.processor() == 's390x' and package == 'dmidecode':
            continue
        if package != "json_version":
            current_package_rc = rpm_is_installed(package)
            expected_package_rc = packages_dictionary[package]
            if current_package_rc == expected_package_rc:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " installation status of " +
                    package +
                    " is as expected")
            else:
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " installation status of " +
                    package +
                    " is *NOT* as expected")
                errors = errors + 1
    return(errors)


def get_system_serial():
    # For now we do OS call, not standarized output on python dmidecode
    fatal_error = False
    system_serial = "00000000"
    if platform.processor() == 's390x':  # No serial# checking on s390x
        return fatal_error, system_serial
    try:
        if PYTHON3:
            system_serial = subprocess.getoutput(
                "dmidecode -s system-serial-number"
            )
        else:
            system_serial = commands.getoutput(
                "dmidecode -s system-serial-number"
            )
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query system serial"
            )
    return fatal_error, system_serial
        

def check_processor():
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking processor compatibility")
    current_processor = platform.processor()
    if current_processor == 'x86_64' or current_processor == 's390x':
        print(
            INFO +
            LOCAL_HOSTNAME +
            " " +
            current_processor +
            " processor is supported to run ECE")
    else:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " " +
            current_processor +
            " processor is not supported to run ECE")
        fatal_error = True
    return fatal_error, current_processor


def check_sockets_cores(min_socket, min_cores):
    fatal_error = False
    cores = []
    if platform.processor() != 's390x':
        print(INFO + LOCAL_HOSTNAME + " checking socket count")
        sockets = dmidecode.processor()
        for socket in sockets.keys():
            socket_version = sockets[socket]['data']['Version'].decode()
        if "AMD" in socket_version:
            is_AMD = True
            pattern_EPYC_1st_gen = re.compile(r'EPYC\s\d{3}1')
            is_EPYC_1st_gen = pattern_EPYC_1st_gen.search(socket_version)
            if is_EPYC_1st_gen:
                fatal_error = True
                print(
                    ERROR + 
                    LOCAL_HOSTNAME + 
                    " AMD EPYC 1st Generation (Naples) is not supported by ECE")
        else:
            is_AMD = False
        num_sockets = len(sockets)
        if is_AMD:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " is AMD based")
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " is Intel based")
        if num_sockets < min_socket:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " has " +
                str(num_sockets) +
                " socket[s] which is less than " +
                str(min_socket) +
                " socket[s] required to support ECE")
            fatal_error = True
        elif num_sockets <= 2:
            # Single and dual sockets(Intel or AMD) are supported
            if is_AMD and num_sockets == 2:
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(num_sockets) +
                    " AMD sockets which may need tuning NPS config to get better performance")
            else:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(num_sockets) +
                    " socket[s] which complies with the requirements to support ECE")
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " has " +
                str(num_sockets) +
                " sockets which is not verified to support ECE")
            fatal_error = True

    print(INFO + LOCAL_HOSTNAME + " checking core count")
    if platform.processor() == 's390x':
        cores =  core_count = multiprocessing.cpu_count()
        num_sockets = min_socket
        if core_count < min_cores:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " has " +
                str(core_count) +
                " core[s] which is less than " +
                str(min_cores) +
                " cores required to run ECE")
            fatal_error = True
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has " +
                str(core_count) +
                " core[s] which copmplies with the requirements to support ECE")
    else:
        total_core_num = 0
        for socket in sockets.keys():
            core_count = sockets[socket]['data']['Core Count']
            # For socket but no chip installed
            if core_count == "None":
                core_count = 0
            if core_count is None:
                core_count = 0
            cores.append(core_count)
            total_core_num = total_core_num + core_count
            print(
                INFO +
                LOCAL_HOSTNAME +
                " socket " +
                str(socket) +
                " has " +
                str(core_count) +
                " core[s]")
        if total_core_num < min_cores:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " has a total of " +
                str(total_core_num) +
                " core[s] which is less than " +
                str(min_cores) +
                " cores required to run ECE")
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has a total of " +
                str(total_core_num) +
                " cores which complies with the requirements to support ECE")
    return fatal_error, num_sockets, cores


def check_memory(min_gb_ram):
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking memory")
    # Total memory
    if platform.processor() == 's390x':
        meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open('/proc/meminfo').readlines())
        mem_kib = meminfo['MemTotal']  # e.g. 3921852
        mem_gb  = round(mem_kib / 1024 / 1024, 2)
    else:
       mem_b = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
       mem_gb = mem_b / 1024**3
    if mem_gb < min_gb_ram:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " total memory is less than " +
            str(min_gb_ram) +
            " GB required to run ECE")
        fatal_error = True
    else:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " total memory is " +
            str(mem_gb) +
            " GB, which is sufficient to run ECE")
    # Memory DIMMs
    if platform.processor() == 's390x':    # no dims on s390x
        dimms = 0
        num_dimms = 0
        empty_dimms = 0
        main_memory_size = 0
    else:
        dimms = {}
        m_slots = dmidecode.memory()
        for slot in m_slots.keys():
            # Avoiding 'System Board Or Motherboard'. Need more data
            if m_slots[slot]['data']['Error Information Handle'] == 'Not Provided':
                continue
            try:
                dimms[m_slots[slot]['data']['Locator']] = m_slots[slot]['data']['Size']
            except BaseException:
                continue
        empty_dimms = 0
        num_dimms = len(dimms)
        dimm_size = {}
        for dimm in dimms.keys():
            if dimms[dimm] is None:
                empty_dimms = empty_dimms + 1
            elif dimms[dimm] == "NO DIMM":
                empty_dimms = empty_dimms + 1
            else:
                dimm_size[dimm] = dimms[dimm]
        if empty_dimms > 0:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all " +
                str(num_dimms) +
                " DIMM slot[s] are populated. This system has " +
                str(empty_dimms) +
                " empty DIMM slot[s]. This is not optimal if NVMe devices are used")
        else:
            print(INFO + LOCAL_HOSTNAME + " all " + str(num_dimms) +
                  " DIMM slot[s] are populated. This is recommended when NVMe devices are used")
        dimm_memory_size = []
        for dimm in dimm_size.keys():
            dimm_memory_size.append(dimm_size[dimm])
        main_memory_size = unique_list(dimm_memory_size)
        if len(main_memory_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all populated DIMM slots have same memory size")
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " all populated DIMM slots do not have same memory sizes")
            fatal_error = True
    return fatal_error, mem_gb, dimms, num_dimms, empty_dimms, main_memory_size


def unique_list(inputlist):
    outputlist = []
    for item in inputlist:
        if item not in outputlist:
            outputlist.append(item)
    return outputlist


def check_os_redhat(os_dictionary):
    redhat8 = False
    fatal_error = False
    # Check redhat-release vs dictionary list
    try:
      redhat_distribution = platform.linux_distribution()
    except AttributeError as E:
        import distro
        redhat_distribution = distro.linux_distribution()

    version_string = redhat_distribution[1]
    try:
        if platform.dist()[0] == "centos":
            matchobj = re.match(OSVERPATT, version_string)
            version_string = "{}.{}".format(matchobj.group('major'),
                                            matchobj.group('minor'))
    except AttributeError:
        pass

    redhat_distribution_str = redhat_distribution[0] + \
        " " + version_string

    if version_string.startswith("8.") or version_string.startswith("9."):
        redhat8 = True

    error_message = ERROR + LOCAL_HOSTNAME + " " + \
        redhat_distribution_str + " is not a supported OS to run ECE\n"
    try:
        if os_dictionary[redhat_distribution_str] == 'OK':
            print(
                INFO +
                LOCAL_HOSTNAME +
                " " +
                redhat_distribution_str +
                " is a supported OS to run ECE")
        elif os_dictionary[redhat_distribution_str] == 'WARN':
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " " +
                redhat_distribution_str +
                " is a clone OS that is not officially supported" +
                " to run ECE." +
                " See Spectrum Scale FAQ for restrictions.")
        else:
            sys.exit(error_message)
            fatal_error = True
    except BaseException:
        sys.exit(error_message)
        fatal_error = True

    return fatal_error, redhat_distribution_str, redhat8


def get_json_versions(
        os_dictionary,
        packages_dictionary,
        SAS_dictionary,
        NIC_dictionary,
        HW_dictionary):

    # Gets the versions of the json files into a dictionary
    json_version = {}

    # Lets see if we can load version, if not quit
    try:
        json_version['supported_OS'] = os_dictionary['json_version']
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot load version from supported OS JSON")

    try:
        json_version['packages'] = packages_dictionary['json_version']
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot load version from packages JSON")

    try:
        json_version['SAS_adapters'] = SAS_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from SAS JSON")

    try:
        json_version['NIC_adapters'] = NIC_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from SAS JSON")

    try:
        json_version['HW_requirements'] = HW_dictionary['json_version']
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot load version from HW JSON")

    # If we made it this far lets return the dictionary. This was being stored
    # in its own file before
    return json_version


def check_NVME():
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " checking NVMe devices")
    try:
        nvme_devices = os.listdir('/sys/class/nvme/')
        num_nvme_devices = len(nvme_devices)
        if num_nvme_devices == 0:
            print(WARNING + LOCAL_HOSTNAME + " no NVMe devices detected")
            fatal_error = True
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has " +
                str(num_nvme_devices) +
                " NVMe device[s] detected")

    except BaseException:
        num_nvme_devices = 0
        print(WARNING + LOCAL_HOSTNAME + " no NVMe devices detected")
        fatal_error = True

    return fatal_error, num_nvme_devices


def check_NVME_packages(packages_ch):
    fatal_error = False
    nvme_packages = {"nvme-cli": 0}
    if packages_ch:
        print(INFO +
        LOCAL_HOSTNAME +
        " checking that needed software for NVMe is installed")
        nvme_packages_errors = packages_check(nvme_packages)
        if nvme_packages_errors:
            fatal_error = True
    return fatal_error


def check_SAS_packages(packages_ch):
    fatal_error = False
    sas_packages = {SAS_TOOL_ALIAS: 0}
    if packages_ch:
        print(INFO +
        LOCAL_HOSTNAME +
        " checking that needed software for SAS is installed")
        sas_packages_errors = packages_check(sas_packages)
        if sas_packages_errors:
            fatal_error = True
    return fatal_error


def check_NVME_disks():
    # If we run this we already check elsewhere that there are NVme drives
    fatal_error = False
    try:
        if PYTHON3:
            drives_raw = subprocess.getoutput("nvme list -o json")
        else:
            drives_raw = commands.getoutput("nvme list -o json")
        drives_dict = {}
        drives_size_list = []
        drives = json.loads(drives_raw)
        for index,single_drive in enumerate(drives['Devices']):
            psize = single_drive['PhysicalSize']
            if psize < 0:
                if PYTHON3:
                    idns_raw = subprocess.getoutput("nvme id-ns "+single_drive['DevicePath'] + " -o json")
                else:
                    idns_raw = commands.getoutput("nvme id-ns "+single_drive['DevicePath'] + " -o json")
                idns = json.loads(idns_raw)
                flbas = idns['flbas']
                lbads = idns['lbafs'][flbas]['ds']
                psize = idns['nsze'] * (1 << lbads)

            drives_dict[index] = [single_drive['DevicePath'],
                                  single_drive['ModelNumber'],
                                  psize,
                                  single_drive['Firmware'],
                                  single_drive['SerialNumber']]
            drives_size_list.append(single_drive['PhysicalSize'])
        drives_unique_size = unique_list(drives_size_list)
        if len(drives_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe devices have the same size")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe devices have the same size")
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query NVMe devices"
            )
    return fatal_error, drives_dict
    
def check_NVME_log_home(drives_dict, size):
    log_home_found = False
    for drive in drives_dict.keys():
        if int(drives_dict[drive][2]) >= size:
            log_home_found = True
            break
    return log_home_found

def check_NVME_ID(drives_dict):
    fatal_error = False
    nvme_id_dict = {}
    eui_list = []
    nguid_list = []
    duplicates = 0
    eui_zero = '0000000000000000'
    nguid_zero = '00000000000000000000000000000000'
    for drive_index in drives_dict.keys():
        drive = drives_dict[drive_index][0]
        try:
            if PYTHON3:
                eui = subprocess.getoutput("nvme id-ns " + drive + " | grep 'eui64' | awk '{print$3}'")
                nguid = subprocess.getoutput("nvme id-ns " + drive + " | grep 'nguid' | awk '{print$3}'")
            else:
                eui = commands.getoutput("nvme id-ns " + drive + " | grep 'eui64' | awk '{print$3}'")
                nguid = commands.getoutput("nvme id-ns " + drive + " | grep 'nguid' | awk '{print$3}'")
        except BaseException:
            fatal_error = True
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " cannot query IDs on NVMe device " +
                drive
                )
        if str(eui) != eui_zero and str(eui) in eui_list:
            duplicates = duplicates + 1
        else:
            eui_list.append(str(eui))

        if str(nguid) != nguid_zero and str(nguid) in nguid_list:
            duplicates = duplicates + 1
        else:
            nguid_list.append(str(nguid))

        nvme_id_dict[drive] = [eui, nguid]

    if fatal_error == False:
        if duplicates > 0:
            fatal_error = True
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " not all NVMe devices have unique IDs")
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe devices have unique IDs")
    return fatal_error, nvme_id_dict



def check_LBA_NVME(drives_dict):
    #We need to check that LBA in use is the same in all drives or fail
    fatal_error = False
    lba_size_list = []
    for drive_index in drives_dict.keys():
        drive = drives_dict[drive_index][0]
        try:
            if PYTHON3:
                lba_size = subprocess.getoutput("nvme id-ns " + drive + " | grep 'in use' | awk '{print$5}' | cut -c7-")
            else:
                lba_size = commands.getoutput("nvme id-ns " + drive + " | grep 'in use' | awk '{print$5}' | cut -c7-")
        except BaseException:
            fatal_error = True
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot query LBA on NVMe device " +
                drive
                )
        lba_size_list.append(lba_size)
    lba_unique_size = unique_list(lba_size_list)
    if fatal_error == False:
        if len(lba_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe devices have the same LBA size")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe devices have the same LBA size")
    return fatal_error


def check_MD_NVME(drives_dict):
    #We need to check that MD in use is the same in all drives or fail
    fatal_error = False
    md_size_list = []
    for drive_index in drives_dict.keys():
        drive = drives_dict[drive_index][0]
        try:
            if PYTHON3:
                md_size = subprocess.getoutput("nvme id-ns " + drive + " | grep 'in use' | awk '{print$4}' | cut -c4-")
            else:
                md_size = commands.getoutput("nvme id-ns " + drive + " | grep 'in use' | awk '{print$4}' | cut -c4-")
        except BaseException:
            fatal_error = True
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " cannot query metadata size on NVMe device " +
                drive
                )
        md_size_list.append(md_size)
    md_unique_size = unique_list(md_size_list)
    if fatal_error == False:
        if len(md_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe devices have the same metadata size")
            if md_size == "0":
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " all NVMe devices have metadata size of zero")
            else:
                fatal_error = True
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " not all NVMe devices have metadata size of zero")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe devices have the same metadata size")
    return fatal_error


def tuned_adm_check():
    errors = 0
    # Is tuned up?
    try:  # Can we run tune-adm?
        return_code = subprocess.call(['systemctl','is-active','tuned'],stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot run systemctl is-active tuned\n")
    if return_code != 0:
        print(ERROR + LOCAL_HOSTNAME + " tuned is not running")
        errors = errors + 1
        return errors
    # Lets have a clean start by restarting the daemon
    try:
        rc_restart = subprocess.call(['systemctl','restart','tuned'],stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot run systemctl restart tuned\n")
    if rc_restart != 0:
        print(ERROR + LOCAL_HOSTNAME + " cannot restart tuned")
        errors = errors + 1
        return errors
    try:  # Can we run tune-adm?
        return_code = subprocess.call(['tuned-adm','active'],stdout=DEVNULL, stderr=DEVNULL)
    except BaseException:
        sys.exit(ERROR + LOCAL_HOSTNAME + " cannot run tuned-adm. It is a needed package for this tool\n") # Not installed or else.

    tuned_adm = subprocess.Popen(['tuned-adm', 'active'], stdout=subprocess.PIPE)
    tuned_adm.wait()
    grep_rc_tuned = subprocess.call(['grep', 'Current active profile: spectrumscale-ece'], stdin=tuned_adm.stdout, stdout=DEVNULL, stderr=DEVNULL)

    if grep_rc_tuned == 0: # throughput-performance profile is active
        print(INFO + LOCAL_HOSTNAME + " current active profile is spectrumscale-ece")
        # try: #Is it fully matching?
        return_code = subprocess.call(['tuned-adm','verify'],stdout=DEVNULL, stderr=DEVNULL)
    
        if return_code == 0:
            print(INFO + LOCAL_HOSTNAME + " tuned is matching the active profile")
        else:
            print(ERROR + LOCAL_HOSTNAME + " tuned profile is *NOT* fully matching the active profile. " +
            "Check 'tuned-adm verify' to check the deviations.")
            errors = errors + 1

    else: #Some error
        print(ERROR + LOCAL_HOSTNAME + " current active profile is not spectrumscale-ece. Please check " + TUNED_TOOL)
        errors = errors + 1

    return errors


def check_SAS(SAS_dictionary):
    fatal_error = False
    check_disks = False
    SAS_model = []
    # do a lspci check if it has at least one adpater from the dictionary
    found_SAS = False
    print(INFO + LOCAL_HOSTNAME + " checking SAS adapters")
    for SAS in SAS_dictionary:
        if SAS != "json_version":
            try:
                lspci_out = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
                grep_proc = subprocess.Popen(['grep', 'SAS'], stdin=lspci_out.stdout, stdout=subprocess.PIPE)
                grep_out_lspci, err = grep_proc.communicate()
                if err != None:
                    # We hit something unexpected
                    fatal_error = True
                SAS_p='\\b'+SAS+'\\b'
                try:
                    this_SAS = re.search(SAS_p,str(grep_out_lspci)).group(0)
                    SAS_var_is_OK = True
                    grep_rc_lspci = 0
                except BaseException:
                    SAS_var_is_OK = False
                    grep_rc_lspci = 1
                if grep_rc_lspci == 0:  # We have this SAS, 1 or more
                    if SAS_dictionary[SAS] == "OK":                       
                        if SAS_var_is_OK:
                            SAS_model.append(this_SAS)
                            storcli_err = check_storcli()
                            sas_speed_err = check_SAS_speed()
                            if (storcli_err and sas_speed_err) == False:
                                found_SAS = True
                                check_disks = True
                                print(
                                    INFO +
                                    LOCAL_HOSTNAME +
                                    " has " +
                                    SAS +
                                    " adapter which is tested by IBM. The disks " +
                                    "under this SAS adapter could be used by ECE"
                                )
                            if storcli_err:
                                found_SAS = False
                                fatal_error = True
                                print(
                                    ERROR +
                                    LOCAL_HOSTNAME +
                                    " has " +
                                    SAS +
                                    " adapter that " +
                                    SAS_TOOL_ALIAS + " cannot manage."
                                )
                            if sas_speed_err:
                                found_SAS = True
                                fatal_error = False
                                print(
                                    WARNING +
                                    LOCAL_HOSTNAME +
                                    " has " +
                                    SAS +
                                    ". Check its fabric speed failed. " +
                                    "Please run storage tool from " +
                                    STORAGE_TOOL
                                )
                    elif SAS_dictionary[SAS] == "NOK":
                        print(
                            ERROR +
                            LOCAL_HOSTNAME +
                            " has " +
                            SAS +
                            " adapter which is NOT supported by ECE.")
                        # Lets not yet enable this check for "all" disks
                        # check_disks = True
                        SAS_model.append(SAS)
                        fatal_error = True
                        found_SAS = False
                    else:
                        print(
                            WARNING +
                            LOCAL_HOSTNAME +
                            " has " +
                            SAS +
                            " adapter which has not been tested.")
                        SAS_model.append("NOT TESTED")
                        storcli_err = check_storcli()
                        sas_speed_err = check_SAS_speed()
                        if (storcli_err and sas_speed_err) == False:
                            found_SAS = True
                            fatal_error = False
                            check_disks = True
                            print(
                                INFO +
                                LOCAL_HOSTNAME +
                                " has " +
                                SAS +
                                " adapter which is supported by ECE. The disks " +
                                "under this SAS adapter could be used by ECE"
                            )
                        if storcli_err:
                            found_SAS = False
                            fatal_error = True
                            print(
                                ERROR +
                                LOCAL_HOSTNAME +
                                " has " +
                                SAS +
                                " adapter that " +
                                SAS_TOOL_ALIAS + " cannot manage."
                            )
                        if sas_speed_err:
                            found_SAS = True
                            fatal_error = False
                            print(
                                WARNING +
                                LOCAL_HOSTNAME +
                                " has " +
                                SAS +
                                ". Check its fabric speed failed. " +
                                "Please run storage tool from " +
                                STORAGE_TOOL
                            )
            except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing SAS adapters")

    if not found_SAS:
        # We hit here is there is no SAS listed on the JSON or no SAS at all
        try:
            lspci_out = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
            grep_proc = subprocess.Popen(['egrep', 'SAS|MegaRAID'], stdin=lspci_out.stdout, stdout=subprocess.PIPE)
            grep_out_lspci, err = grep_proc.communicate()
            if err != None:
                # We hit something unexpected
                fatal_error = True
            if grep_proc.returncode == 0: # We have some SAS
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has a non tested SAS adapter")
                #check_disks = True
                SAS_model.append("NOT TESTED")
                storcli_works = check_storcli()
                sas_dev_int = check_SAS_speed()
                if (storcli_works and sas_dev_int) == False:
                    found_SAS = True
                    check_disks = True
                if storcli_works:
                    found_SAS = False
                    fatal_error = True
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has an adapter that " +
                        SAS_TOOL_ALIAS + " cannot manage.")
                if sas_dev_int:
                    found_SAS = False
                    fatal_error = False
                    print(
                        WARNING +
                        LOCAL_HOSTNAME +
                        " SAS adapater fabric speed failed check. " +
                        "Please run storage tool from " +
                        STORAGE_TOOL
                    ) 
            else:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " does not have any SAS adapter.")
        except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing SAS adapters")
    return fatal_error, check_disks, SAS_model


def exec_cmd(command):
    # write command to JSON to have an idea of the system

    try:
        run_cmd = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
        cmd_output, cmd_stderr = run_cmd.communicate()
        return cmd_output.strip()

    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot run " + str(command))


def check_storcli():
    try:
        if PYTHON3:
            sas_int = subprocess.getoutput(
                SAS_TOOL + " show " +
                "| grep Number | awk '{print$5}'")
        else:
            sas_int = commands.getoutput(
                SAS_TOOL + " show " +
                "| grep Number | awk '{print$5}'")
        
        if sas_int == '0':
            fatal_error = True
        else:
            fatal_error = False
    except BaseException:
        fatal_error = True
    return fatal_error


def check_SAS_speed():
    allowed_dev_int = '12G'
    fatal_error = False
    try:
        if PYTHON3:
            sas_speed = subprocess.getoutput(
                SAS_TOOL + " /call show all" +
                "| grep \"Device Interface\" | sort -u | awk '{print $4}'")
        else:
            sas_speed = commands.getoutput(
                SAS_TOOL + " /call show all" +
                "| grep \"Device Interface\" | sort -u | awk '{print $4}'")
        
        if  allowed_dev_int in sas_speed:
            fatal_error = False
            print(
                INFO +
                LOCAL_HOSTNAME +
                " has a fabric SAS speed of " +
                sas_speed +
                " for its fabric. Please rememeber to run the Storage " +
                "acceptance tool that can be found at " + 
                STORAGE_TOOL
            )
        else:
            # We just print a warning for now
            fatal_error = False
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " has a fabric SAS speed that is not 12G. It reports " +
                sas_speed +
                " for its fabric. Please rememeber to run the Storage " +
                "acceptance tool that can be found at " + 
                STORAGE_TOOL
            )
    except BaseException:
        fatal_error = True
    return fatal_error

def dpofua_check(sata_drive):
    # We are going to check DpoFua = 1
    try:
        if PYTHON3:
            sg_modes_output = subprocess.getoutput(
                '/bin/sg_modes ' +
                sata_drive + 
                ' | grep DpoFua')
        else:
            sg_modes_output = commands.getoutput(
                '/bin/sg_modes ' +
                sata_drive + 
                ' | grep DpoFua')
        # We got a line like
        #   Mode data length=44, medium type=0x00, WP=0, DpoFua=0, longlba=0
        # Lets clean the spaces first
        sg_modes_output = sg_modes_output.replace(" ", "")
        # Lets split by ,
        dpofua = sg_modes_output.split(",")[3]
        if "DpoFua" not in dpofua:
            # We did not wrap it correctly
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot check DpoFua value on SATA drive " +
                str(sata_drive)
            )
            dpofua_check_passed = False
        else:
            dpofua_value = dpofua[-1]
            if dpofua_value == "1":
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " DpoFua value on SATA drive " +
                    str(sata_drive) +
                    " is 1"
                )
                dpofua_check_passed = True
            else:
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " DpoFua value on SATA drive " +
                    str(sata_drive) +
                    " is not 1"
                )
                dpofua_check_passed = False
    except BaseException:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot check DpoFua value on SATA drive " +
            str(sata_drive)
        )
        dpofua_check_passed = False
    return dpofua_check_passed   


def sct_erc_check(sata_drive):
    # We are going to check SCT Error Recovery Control Read/Write time <= 10
    try:
        if PYTHON3:
            smartctl_output = subprocess.getoutput(
                '/sbin/smartctl -l scterc ' +
                sata_drive + 
                ' | grep seconds')
        else:
            smartctl_output = commands.getoutput(
                '/sbin/smartctl -l scterc ' +
                sata_drive + 
                ' | grep seconds')
        # We got two lines like (or none if no support on drive for SCT)
        #  Read: 70 (7.0 seconds)
        #  Write: 70 (7.0 seconds)
        if "seconds" in smartctl_output:
            # We got some output
            output_by_line = smartctl_output.splitlines()
            if len(output_by_line) == 2:
                # We move on, clean multiple spaces, just in case
                output_read = re.sub('\s{2,}',' ',output_by_line[0])
                output_write = re.sub('\s{2,}',' ',output_by_line[1])
                # If exception we fall back to except already defined
                sct_erc_read = int(output_read.split(" ")[2])
                sct_erc_write = int(output_write.split(" ")[2])
                if (sct_erc_read and sct_erc_write) <= 100:
                    # We have both more than 10 seconds
                    print(
                        INFO +
                        LOCAL_HOSTNAME +
                        " SCT ERC read/write values on SATA drive " +
                        str(sata_drive) + 
                        " are set 10 seconds or less"
                    )
                    sct_erc_check_passed = True
                    return sct_erc_check_passed
                else:
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " SCT ERC read/write value on SATA drive " +
                        str(sata_drive) + 
                        " is set to more than 10 seconds"
                    )
                    sct_erc_check_passed = False
                    return sct_erc_check_passed
            else:
                # Something is not right, we fail
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " cannot check SCT ERC read/write value on SATA drive " +
                    str(sata_drive)
                )
                sct_erc_check_passed = False
        else:
            print(
            ERROR +
            LOCAL_HOSTNAME +
            " does not support SCT ERC on SATA drive " +
            str(sata_drive)
        )
        sct_erc_check_passed = False
    except BaseException:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot check SCT ERC value on SATA drive " +
            str(sata_drive)
        )
        sct_erc_check_passed = False
    return sct_erc_check_passed   


def sata_checks(SATA_drives):
    # We do perform some SATA checks
    errors = 0
    for sata_drive in SATA_drives:
        dpofua_pass = dpofua_check(sata_drive)
        if dpofua_pass == False:
            errors = errors + 1
        sct_erc_pass = sct_erc_check(sata_drive)
        if sct_erc_pass == False:
            errors = errors + 1
        
    if errors == 0:
        all_sata_drives_pass = True
    else:
        all_sata_drives_pass = False
    return all_sata_drives_pass


def check_SAS_disks(device_type, sata_on):
    fatal_error = False
    num_errors = 0
    number_of_drives = 0
    number_of_SATA_drives = 0
    SAS_drives_dict = {}
    try:
        if PYTHON3:
            drives = subprocess.getoutput(
                SAS_TOOL + " /call show " +
                "| egrep \"JBOD|UGood\" | grep SAS | tr -s ' ' ' ' | sort -u |grep " +
                device_type).splitlines()
            SATA_drives = subprocess.getoutput(
                SAS_TOOL + " /call show " +
                "| grep SATA | egrep \"JBOD|UGood\" | tr -s ' ' ' ' | sort -u | grep " +
                device_type).splitlines()
        else:
            drives = commands.getoutput(
                SAS_TOOL + " /call show " +
                "| egrep \"JBOD|UGood\" | grep SAS | tr -s ' ' ' ' | sort -u | grep " +
                device_type).splitlines()
            SATA_drives = commands.getoutput(
                SAS_TOOL + " /call show " +
                "| grep SATA | egrep \"JBOD|UGood\" | tr -s ' ' ' ' | sort -u | grep " +
                device_type).splitlines()
        number_of_drives = len(drives)
        number_of_SATA_drives = len(SATA_drives)

        if number_of_SATA_drives > 0:
            if sata_on:
                sata_checks_passed = False
                # We are going to do some SATA checks
                if PYTHON3:
                    SATA_OS_drives = subprocess.getoutput(
                        "/usr/bin/lsscsi | grep ATA | awk '{print$NF}'"
                    ).splitlines()
                else:
                    SATA_OS_drives = commands.getoutput(
                        "/usr/bin/lsscsi | grep ATA | awk '{print$NF}'"
                    ).splitlines()
                if len(SATA_OS_drives) == number_of_SATA_drives:
                    # All SATA are JBOD and no OS
                    sata_checks_passed = sata_checks(SATA_OS_drives)
                else:
                    # We need to get out OS drive
                    if PYTHON3:
                        partition_drives = subprocess.getoutput(
                            "cat /proc/mounts | grep '/dev\/sd' | awk '{print $1}'"
                        ).splitlines()
                    else:
                        partition_drives = commands.getoutput(
                            "cat /proc/mounts | grep '/dev\/sd' | awk '{print $1}'"
                        ).splitlines()
                    clean_partition_drives = []
                    for part in partition_drives:
                        clean_partition_drives.append(part[:-1])
                    uniq_partition_drives = set(clean_partition_drives)
                    SATA_OS_drives_to_check = list(set(SATA_OS_drives).difference(uniq_partition_drives))
                    # We have a JBOD on OS issue here
                    sata_checks_passed = sata_checks(SATA_OS_drives_to_check)
                if sata_checks_passed:
                    # While we still pass the SATA checks we mark a fail here
                    # Someone has run this wiht SATA option so we wnat to cover a PASS
                    # When/If SATA goes GA the following line should be deleted
                    num_errors = num_errors + 1
                    print(
                        WARNING +
                        LOCAL_HOSTNAME +
                        " has " +
                        str(number_of_SATA_drives) +
                        " SATA " +
                        device_type +
                        " drive[s] on the SAS adapter. While those pass the " +
                        "performed checks SATA drives are not supported by " +
                        "ECE. Do not use them for ECE"
                    )
                else:
                    # SATA not supported and so we mark as failed
                    num_errors = num_errors + 1
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has " +
                        str(number_of_SATA_drives) +
                        " SATA " +
                        device_type +
                        " drive[s] on the SAS adapter. Those do not pass the " +
                        "performed checks. SATA drives are not supported by " +
                        "ECE. Do not use them for ECE"
                    )

            else:
                # Throw a warning about presence of SATA drives
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(number_of_SATA_drives) +
                    " SATA " +
                    device_type +
                    " drive[s] on the SAS adapter. SATA drives are not" +
                    " supported by ECE. Do not use them for ECE"
                )

        if number_of_drives > 0:
            drives_size_list = []
            for single_drive in drives:
                list_single_drive = single_drive.split()
                SAS_drives_dict[list_single_drive[0]] = [
                    list_single_drive[4],
                    list_single_drive[5],
                    list_single_drive[10],
                    list_single_drive[11]]
                drives_size_list.append(list_single_drive[4])

            drives_unique_size = unique_list(drives_size_list)
            if len(drives_unique_size) == 1:
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(number_of_drives) +
                    " " +
                    device_type +
                    " drive[s] on the SAS adapter the same size " +
                    "that ECE can use")
            else:
                # We should fail here if different sizes, but lets make warning
                # num_errors = num_errors + 1
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has " +
                    str(number_of_drives) +
                    " " +
                    device_type +
                    " drive[s] on the SAS adapter with different sizes " +
                    "that ECE can use")
        else:
            num_errors = num_errors + 1
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " has " +
                str(number_of_drives) +
                " " +
                device_type +
                " drive[s] that ECE can use")

    except BaseException:
        num_errors = num_errors + 1
        number_of_drives = 0
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " no " +
            device_type +
            " disk[s] usable by ECE found. The drives under SAS controller " +
            "must be on JBOD mode and be SAS drives")

    if num_errors != 0:
        fatal_error = True

    return fatal_error, number_of_drives, SAS_drives_dict
    
def check_SSD_loghome(SSD_dict, size):
    log_home_found = False
    print(SSD_dict)
    for SSD in SSD_dict:
        if convert_to_bytes(int(float(SSD_dict[SSD][0])),SSD_dict[SSD][1]) >= size:
            log_home_found = True
            break
    return log_home_found


def check_WCE_NVME(NVME_dict):
    num_errors = 0
    fatal_error = False
    for drive in NVME_dict.keys():
        os_device = NVME_dict[drive][0]
        wce_drive_enabled = False
        try:
            if PYTHON3:
                rc, write_cache_drive = subprocess.getstatusoutput(
                    '/usr/bin/sginfo -c ' + os_device +
                    "| grep 'Write Cache' | awk {'print$4'}")
            else:
                rc, write_cache_drive = commands.getstatusoutput(
                    '/usr/bin/sginfo -c ' + os_device +
                    "| grep 'Write Cache' | awk {'print$4'}")
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for NVMe devices")

        # if WCE is not supported on device then we expect nonzero rc
        if rc == 0:
            try:
                wce_drive_enabled = bool(int(write_cache_drive))
                NVME_dict[drive].append(wce_drive_enabled)
            except BaseException:
                # It gave RC0 but it has not such feature
                wce_drive_enabled = False

        if wce_drive_enabled:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(os_device) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1
    if num_errors != 0:
        fatal_error = True
    else:
        print(INFO + LOCAL_HOSTNAME + " all NVME drives have Volatile Write" +
              " Cache disabled")

    return fatal_error, NVME_dict


def check_WCE_SAS(SAS_drives_dict):
    # Check WCE is enabled, if so print an ERROR + return fatal_error True
    fatal_error = False
    num_errors = 0
    for drive in SAS_drives_dict.keys():
        enc_slot_list = drive.split(':')
        try:
            if PYTHON3:
                storcli_output = subprocess.getoutput(
                    SAS_TOOL + ' /call/e' +
                    enc_slot_list[0] + '/s' + enc_slot_list[1] + ' show all j ')
            else:
                storcli_output = commands.getoutput(
                    SAS_TOOL + ' /call/e' + enc_slot_list[0] +
                    '/s' + enc_slot_list[1] + ' show all j ')
            wwn = WWNPATT.search(storcli_output).group('wwn')
            sasaddr = SASPATT.search(storcli_output).group('sasaddr')
            if wwn == 'NA':
                # if wwn is not defined, use sasaddr - we truncate last
                # digit later
                wwn = sasaddr
        except BaseException as e:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot parse WWN for SAS devices")
        SAS_drives_dict[drive].append(wwn.lower())
        map_error, os_device = map_WWN_to_OS_device(wwn.lower())
        if map_error:  # We need to exit
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot map drive from WWN " +
                wwn +
                " to its OS name. Please run 'rescan-scsi-bus.sh' " +
                "in this node and try again"
            ) 
        SAS_drives_dict[drive].append(map_error)
        SAS_drives_dict[drive].append(os_device)
        wce_drive_enabled = False
        try:
            if PYTHON3:
                rc, write_cache_drive = subprocess.getstatusoutput(
                    '/usr/bin/sginfo -c /dev/' + os_device +
                    "| grep 'Write Cache' | awk {'print$4'}")
            else:
                rc, write_cache_drive = commands.getstatusoutput(
                    '/usr/bin/sginfo -c /dev/' + os_device +
                    "| grep 'Write Cache' | awk {'print$4'}")
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for SAS devices")

        # if WCE is not supported on device the we expect nonzero rc
        if rc == 0:
            wce_drive_enabled = bool(int(write_cache_drive))
            SAS_drives_dict[drive].append(wce_drive_enabled)

        if wce_drive_enabled:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(os_device) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1

        # why do we need to check again with storcli?
        try:
            if PYTHON3:
                write_cache_list = subprocess.getoutput(
                    SAS_TOOL + ' /call/e' +
                    enc_slot_list[0] +
                    '/s' + enc_slot_list[1] +
                    ' show all | grep -i "Write Cache"').split(' ')
            else:
                write_cache_list = commands.getoutput(
                    SAS_TOOL + ' /call/e' +
                    enc_slot_list[0] +
                    '/s' + enc_slot_list[1] +
                    ' show all | grep -i "Write Cache"').split(' ')
        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot read WCE status for SAS card")

        # if write cache entry is returned by storcli, use it
        # otherwise ignore
        if len(write_cache_list) > 3:
            wc_status = write_cache_list[3]
            SAS_drives_dict[drive].append(write_cache_list[3])
        else:
            wc_status = 'Unsupported'

        SAS_drives_dict[drive].append(wc_status)
        if wc_status == "Enabled":
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                str(drive) +
                " has Write Cache Enabled. This is not supported by ECE")
            num_errors = num_errors + 1
    if num_errors != 0:
        fatal_error = True
    else:
        print(INFO + LOCAL_HOSTNAME +
              " all SAS drives have Volatile Write Cache disabled")

    return fatal_error, SAS_drives_dict


def map_WWN_to_OS_device(drive_WWN):
    fatal_error = False
    num_errors = 0
    # ignore the least signicant digit - this is enough to uniquely ID
    # drives by WWN.  (but need all other digits - here is an example
    # where ignoring last 2 digits causes a problem:
    # # lsscsi -w | grep 0x50000397c82ac4
    # [1:0:20:0]   disk    0x50000397c82ac4b9                  /dev/sdt
    # [1:0:21:0]   disk    0x50000397c82ac461                  /dev/sdu
    # [1:0:23:0]   disk    0x50000397c82ac42d                  /dev/sdw
    truncated_WWN = drive_WWN[:-1]
    try:
        if PYTHON3:
            OS_drive_list = subprocess.getoutput(
                '/usr/bin/readlink /dev/disk/by-id/wwn-0x' + truncated_WWN +
                '? | /usr/bin/head -1').split('/')
        else:
            OS_drive_list = commands.getoutput(
                '/usr/bin/readlink /dev/disk/by-id/wwn-0x' + truncated_WWN +
                '? | /usr/bin/head -1').split('/')
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " cannot parse WWN from SAS devices")
    try:
        os_device = OS_drive_list[2]
    except BaseException:
        os_device = "NONE"
        num_errors = num_errors + 1

    if num_errors != 0:
        fatal_error = True
    return fatal_error, os_device

def check_is_hipersocket_NIC(net_interface):
    is_hipersocket = False
    try:
        card_type = subprocess.getoutput(
            '/usr/sbin/lsqeth ' + net_interface + ' | grep card_type ' )
        card_type = card_type.split()
        if card_type[2] == 'HiperSockets':
            is_hipersocket = True
        else:
            # checking if Hipersockets interface is bonded
            bondedIfs = subprocess.getoutput(
            'ls -d /sys/class/net/'+net_interface+'/lower_* | awk -Flower_ {\'print $2\'} ')
            # loop through bonded interfaces and check if any is of type Hipersockets 
            for bondedIf in bondedIfs.split():
                card_type = subprocess.getoutput(
                '/usr/sbin/lsqeth ' + bondedIf + ' | grep card_type ' )
                card_type = card_type.split()
                if card_type[2] == 'HiperSockets':
                    is_hipersocket = True
                    break
            
    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " NIC card_type Hipersockets  could not be determined ")

    return is_hipersocket    
    
def check_is_roce_NIC(net_interface):
    is_roce_NIC = False
    try:
        # get all RoCE interfaces
        roceInterfaces = subprocess.getoutput(
            '/usr/sbin/rdma link show -jp | grep netdev\\" | awk -F\\" {\'print " "$4" "\'} | tr \'\\n\' \' \' ')
        # check if word net_interface is among roceInterfaces 
        if " "+net_interface+" " in roceInterfaces:
            is_roce_NIC = True
        else:
            # checking if RoCE interface is bonded 
            bondedIfs = subprocess.getoutput(
            'ls -d /sys/class/net/'+net_interface+'/lower_* | awk -Flower_ {\'print $2\'} ')
            # loop through bonded interfaces and check if any is among roceInterfaces 
            for bondedIf in bondedIfs.split():
                if " "+bondedIf+" " in roceInterfaces:
                    is_roce_NIC = True
                    break

    except BaseException:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " NIC card_type RoCE could not be determined ")

    return is_roce_NIC


def check_NIC(NIC_dictionary,ip_address):
    fatal_error = False
    NIC_model = []
    # do a lspci check if it has at least one adpater from the dictionary
    found_NIC = False
    print(INFO + LOCAL_HOSTNAME + " checking NIC adapters")
    if platform.processor() == 's390x':
        net_devices = list_net_devices()
        try:
            fatal_error, net_interface = what_interface_has_ip(
                net_devices, ip_address)

        except BaseException:
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " an undetermined error ocurred while " +
                "determing which NIC adapters runs IP:" +
                ip_address)

        if not fatal_error:

            try:
                is_hipersocket_NIC = check_is_hipersocket_NIC(net_interface)
                
                if is_hipersocket_NIC: 
                    print(
                        INFO +
                        LOCAL_HOSTNAME +
                        " has " +
                        net_interface +
                        " hipersocket adapter which is supported by ECE")
                    found_NIC = True

            except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing if we run on hipersockets NIC")

            try:
                is_roce_NIC = check_is_roce_NIC(net_interface)

                if is_roce_NIC:
                    print(
                        INFO +
                        LOCAL_HOSTNAME +
                        " has " +
                        net_interface +
                        " RoCE adapter which is supported by ECE")
                    found_NIC = True

                if not found_NIC:
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " IP:" +
                        ip_address +
                        " does not run on neither hipersockets nor RoCE adapter. " +
                        "This is mandatory in order to run ECE on s390x")
                    fatal_error = True

            except BaseException:
                sys.exit(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " an undetermined error ocurred while " +
                    "determing if we run on RoCE")



    else:
        for NIC in NIC_dictionary:
            if NIC != "json_version":
                try:
                    lspci_out = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
                    grep_rc_lspci = subprocess.call(
                        ['grep', NIC],
                        stdin=lspci_out.stdout,
                        stdout=DEVNULL,
                        stderr=DEVNULL)
                    lspci_out.wait()

                    if grep_rc_lspci == 0:  # We have this NIC, 1 or more
                        if NIC_dictionary[NIC] == "OK":
                            print(INFO + LOCAL_HOSTNAME + " has " + NIC +
                                 " adapter which is supported by ECE")
                            found_NIC = True
                            NIC_model.append(NIC)
                        else:
                            print(
                                ERROR +
                                LOCAL_HOSTNAME +
                                " has " +
                                NIC +
                                " adapter which is explicitly not supported by " +
                                "ECE")
                            found_NIC = False
                            fatal_error = True
                            NIC_model.append(NIC)

                except BaseException:
                    sys.exit(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " an undetermined error ocurred while " +
                        "determing NIC adapters")

    if not found_NIC:
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " does not have NIC adapter supported by ECE")
        fatal_error = True

    return fatal_error, NIC_model


def check_distribution():
    # Decide if this is a redhat or a suse
    if PYTHON3:
        what_dist = distro.distro_release_info()['id']
    else:
        what_dist = platform.dist()[0]
    if what_dist in ["redhat", "centos"]:
        return what_dist
    else:  # everything else we fail
        print(ERROR + LOCAL_HOSTNAME + " ECE is only supported on RedHat")
        return "UNSUPPORTED_DISTRIBUTION"


def check_py3_yaml():
    # YAML is not needed for this tool but Scale 5.1.0+
    if PYTHON3:
        try:
            import yaml
            print(
                INFO +
                LOCAL_HOSTNAME +
                " python 3 YAML module found"
            )
            return False
        except ImportError:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " python 3 YAML module not found, please install it " +
                "and run this tool again"
            )
            return True
    else:
        try:
            py3_yaml = commands.getoutput( 'pydoc3 -k yaml ' + ' | grep "yaml"').split()
        except BaseException:
            py3_yaml = False
        if py3_yaml:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " python 3 YAML module found"
            )
            return False
        else:
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " python 3 YAML module not found, please install it " +
                "and run this tool again"
            )
            return True


def print_summary_toolkit():
    # We are here so we need to raise an error RC to be catched by the toolkit
    print(
        ERROR +
        LOCAL_HOSTNAME +
        " does not have a supported configuration to run ECE")


def print_summary_standalone(
        nfatal_errors,
        outputfile_name,
        start_time_date,
        end_time_date,
        redhat_distribution_str,
        current_processor,
        num_sockets,
        core_count,
        mem_gb,
        num_dimms,
        empty_dimms,
        SAS_model,
        number_of_HDD_drives,
        number_of_SSD_drives,
        number_of_NVME_drives,
        NIC_model,
        device_speed,
        all_checks_on,
        sata_on):
    # This is not being run from the toolkit so lets write a more human summary
    print("")
    print("\tSummary of this standalone run:")
    print("\t\tRun started at " + str(start_time_date))
    print("\t\tECE Readiness version " + MOR_VERSION)
    print("\t\tHostname: " + LOCAL_HOSTNAME)
    print("\t\tOS: " + redhat_distribution_str)
    print("\t\tArchitecture: " + str(current_processor))
    if platform.processor() == 's390x':
        print("\t\tCPUs " + str(core_count))
        print("\t\tMemory: " + str(mem_gb) + " GBytes")
    else:
        print("\t\tSockets: " + str(num_sockets))
        print("\t\tCores per socket: " + str(core_count))
        print("\t\tMemory: " + str(mem_gb) + " GBytes")
        print("\t\tDIMM slots: " + str(num_dimms))
        print("\t\tDIMM slots in use: " + str(num_dimms - empty_dimms))
        print("\t\tSAS HBAs in use: " + ', '.join(SAS_model))
        print("\t\tJBOD SAS HDD drives: " + str(number_of_HDD_drives))
        print("\t\tJBOD SAS SSD drives: " + str(number_of_SSD_drives))
        print("\t\tHCAs in use: " + ', '.join(NIC_model))
    print("\t\tNVMe drives: " + str(number_of_NVME_drives))
    print("\t\tLink speed: " + str(device_speed))
    print("\t\tRun ended at " + str(end_time_date))
    print("")
    print("\t\t" + outputfile_name + " contains information about this run")
    print("")

    if sata_on:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " SATA tests were performed, even if this system gave a " +
            "passed status SATA drives cannot be used on ECE. Besides of " +
            "a non supported setup by IBM. " +
            "Be aware you might have data loss if you ignore this warning"
        )

    if nfatal_errors > 0:
        sys.exit(
            ERROR +
            LOCAL_HOSTNAME +
            " system cannot run IBM Spectrum Scale Erasure Code Edition")
    elif all_checks_on:
        print(
            INFO +
            LOCAL_HOSTNAME +
            " system can run IBM Spectrum Scale Erasure Code Edition")
        if sata_on:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " SATA tests were performed, even this system gave a " +
                "passed status SATA drives cannot be used on ECE. Besides of " +
                "a non supported setup by IBM you might face data loss"
            )
    else:
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " Although the tests run were passed some tests were skipped so " +
            "this tool cannot assess if this system can run " +
            "IBM Spectrum Scale Erasure Code Edition")


def main():
    nfatal_errors = 0
    outputfile_dict = {}

    # Start time
    outputfile_dict['start_time'] = str(start_time_date)

    # Save script version into JSON
    outputfile_dict['MOR_VERSION'] = MOR_VERSION

    # Parse ArgumentParser
    (fips_mode,
    ip_address,
    path,
    cpu_check,
    md5_check,
    mem_check,
    os_check,
    packages_ch,
    storage_check,
    net_check,
    tuned_check,
    sata_on,
    toolkit_run,
    want_verbose) = parse_arguments()
    
    date_for_log = str(start_time_date).replace(" ", "_")
    set_logger_up(
        path, 
        "mor_debug_" + date_for_log,
        want_verbose)
    logging.debug(
        "We are runnig on architecture:" +
        str(platform.processor())
    )
    logging.debug(
        "Going to check if all tests are enabled"
    )
    if (cpu_check and md5_check and mem_check and os_check and packages_ch
            and storage_check and net_check):
        all_checks_on = True
        logging.debug(
            "All tests are enabled"
        )
    else:
        all_checks_on = False
        logging.debug(
            "Not all tests are enabled"
        )

    if sata_on:
        logging.debug(
           "SATA checks are enabled"
        )
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " SATA checks are enabled. This is not to be used on any " +
            "environent even if the checks are passed"
        )
    else:
        logging.debug(
            "SATA checks are not enabled"
        )

    # JSON loads and calculate and store MD5
    logging.debug(
        "Going to load the JSON files"
    )
    os_dictionary = load_json(path + "supported_OS.json")
    packages_dictionary = load_json(path + "packages.json")
    SAS_dictionary = load_json(path + "SAS_adapters.json")
    NIC_dictionary = load_json(path + "NIC_adapters.json")
    HW_dictionary = load_json(path + "HW_requirements.json")
    logging.debug(
        "JSON files loaded"
    )
    if fips_mode:
        logging.debug(
            "FIPS mode enabled"
        )
        print(
            ERROR +
            LOCAL_HOSTNAME +
            " This is running with FIPS mode enabled.")
        nfatal_errors = nfatal_errors + 1
        md5_check = False
        supported_OS_md5 = "FIPS"
        packages_md5 = "FIPS"
        SAS_adapters_md5 = "FIPS"
        NIC_adapters_md5 = "FIPS"
        HW_requirements_md5 = "FIPS"
    else:
        logging.debug(
            "FIPS mode not enabled. Going to calculate MD5 SUMs"
        )
        supported_OS_md5 = md5_chksum(path + "supported_OS.json")
        packages_md5 = md5_chksum(path + "packages.json")
        SAS_adapters_md5 = md5_chksum(path + "SAS_adapters.json")
        NIC_adapters_md5 = md5_chksum(path + "NIC_adapters.json")
        HW_requirements_md5 = md5_chksum(path + "HW_requirements.json")
        logging.debug(
            "All MD5 SUMs of JSON files calculated"
        )
    logging.debug(
        "Going to write in dictionary calculated MD5 SUMs"    
    )
    outputfile_dict['supported_OS_md5'] = supported_OS_md5
    outputfile_dict['packages_md5'] = packages_md5
    outputfile_dict['SAS_adapters_md5'] = SAS_adapters_md5
    outputfile_dict['NIC_adapters_md5'] = NIC_adapters_md5
    outputfile_dict['HW_requirements_md5'] = HW_requirements_md5
    logging.debug(
        "Calculated MD5 SUMs written into dictionary"
    )


    # Check MD5 hashes. Files are already checked that exists and load JSON
    logging.debug(
        "Going to verify supported_OS.json"
    )
    passed_md5_supported_os = md5_verify(
        md5_check,
        "supported_OS.json",
        supported_OS_md5,
        SUPPORTED_OS_MD5)
    logging.debug(
        "Verification passed=" +
        str(passed_md5_supported_os)
    )
    outputfile_dict['passed_md5_supported_os'] = passed_md5_supported_os
    logging.debug(
        "Going to verify packages.json"
    )
    passed_md5_packages = md5_verify(
        md5_check,
        "packages.json",
        packages_md5,
        PACKAGES_MD5)
    logging.debug(
        "Verification passed=" +
        str(passed_md5_packages)
    )
    outputfile_dict['passed_md5_packages'] = passed_md5_packages
    logging.debug(
        "Going to verify SAS_adapters.json"
    )
    passed_md5_SAS_adapters = md5_verify(
        md5_check,
        "SAS_adapters.json",
        SAS_adapters_md5,
        SAS_ADAPTERS_MD5)
    logging.debug(
        "Verification passed=" +
        str(passed_md5_SAS_adapters)
    )
    outputfile_dict['passed_md5_SAS_adapters'] = passed_md5_SAS_adapters
    logging.debug(
        "Going to verify NIC_adapters.json"
    )
    passed_md5_NIC_adapters = md5_verify(
        md5_check,
        "NIC_adapters.json",
        NIC_adapters_md5,
        NIC_ADAPTERS_MD5)
    logging.debug(
        "Verification passed=" +
        str(passed_md5_NIC_adapters)
    )
    outputfile_dict['passed_md5_NIC_adapters'] = passed_md5_NIC_adapters
    logging.debug(
        "Going to verify HW_requirements.json"
    )
    passed_md5_HW_requirements = md5_verify(
        md5_check,
        "HW_requirements.json",
        HW_requirements_md5,
        HW_REQUIREMENTS_MD5)
    outputfile_dict['passed_md5_HW_requirements'] = passed_md5_HW_requirements
    logging.debug(
        "Verification passed=" +
        str(passed_md5_HW_requirements)
    )
    # Initial header and checks
    logging.debug(
        "Going to get JSON headers"
    )
    json_version = get_json_versions(
        os_dictionary,
        packages_dictionary,
        SAS_dictionary,
        NIC_dictionary,
        HW_dictionary)
    logging.debug(
        "Got JSON headers"
    )
    logging.debug(
        "Going to show header and ask for permission to run"
    )
    show_header(MOR_VERSION, json_version, toolkit_run)
    logging.debug(
        "Printed header and accepted to run"
    )

    # Set HW constants
    logging.debug(
        "Going to set HW requirements into variables"
    )
    if platform.processor() == 's390x':
        min_socket = HW_dictionary['MIN_SOCKET_S390X']
        min_cores = HW_dictionary['MIN_CORES_S390X']
        min_gb_ram = HW_dictionary['MIN_GB_RAM_S390X']
        max_drives = HW_dictionary['MAX_DRIVES_S390X']
        min_link_speed = HW_dictionary['MIN_LINK_SPEED_S390X']
    else:
        min_socket = HW_dictionary['MIN_SOCKET']
        min_cores = HW_dictionary['MIN_CORES']
        min_gb_ram = HW_dictionary['MIN_GB_RAM']
        max_drives = HW_dictionary['MAX_DRIVES']
        min_link_speed = HW_dictionary['MIN_LINK_SPEED']
        min_loghome_size = HW_dictionary['MIN_LOGHOME_DRIVE_SIZE']

    logging.debug(
        "HW requirements are: min_socket " +
        str(min_socket) +
        " min_cores " +
        str(min_cores) +
        " min_gb_ram " +
        str(min_gb_ram) +
        " max_drives " +
        str(max_drives) +
        " min_link_speed " +
        str(min_link_speed)
    )

    logging.debug(
        "Going to write to dictionary the parameters of this run"
    )
    outputfile_dict['parameters'] = [
        LOCAL_HOSTNAME,
        ip_address,
        path,
        cpu_check,
        md5_check,
        mem_check,
        os_check,
        packages_ch,
        storage_check,
        net_check,
        min_socket,
        min_cores,
        min_gb_ram,
        max_drives,
        min_link_speed]
    logging.debug(
        "Parameters of this run written"
    )

    # Check root
    logging.debug(
        "Going to check if we are root"
    )
    check_root_user()
    logging.debug(
        "root check passed"
    )

    # Check cpu
    logging.debug(
        "Starting CPU checks"
    )
    current_processor = "NOT CHECKED"
    num_sockets = 0
    core_count = 0
    if cpu_check:
        logging.debug(
            "CPU check is enabled"
        )
        logging.debug(
            "Going to call check_processor()"
        )
        fatal_error, current_processor = check_processor()
        logging.debug(
            "Got back from check_processor(). fatal_error=" +
            str(fatal_error) +
            " and current_processor=" +
            str(current_processor)
        )
        outputfile_dict['current_processor'] = current_processor
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
            logging.debug(
                "Number of nfatal_errors is " +
                str(nfatal_errors)
            )
        logging.debug(
            "Going to call check_sockets_cores(" +
            str(min_socket) +
            ", " +
            str(min_cores) +
            ")" 
        )
        fatal_error, num_sockets, core_count = check_sockets_cores(
            min_socket, min_cores)
        logging.debug(
            "Got back from check_sockets_cores. fatal_error=" +
            str(fatal_error) +
            ", num_sockets=" +
            str(num_sockets) +
            ", core_count=" +
            str(core_count)

        )
        outputfile_dict['num_sockets'] = num_sockets
        outputfile_dict['cores_per_socket'] = core_count
        outputfile_dict['CPU_fatal_error'] = fatal_error
        if fatal_error:
            nfatal_errors = nfatal_errors + 1

    # Check linux_distribution
    redhat_distribution_str = "NOT CHECKED"
    logging.debug(
        "Going to check the RedHat Linux distribution"
    )
    # Need this part out of OS check in case it is disabled by user
    if PYTHON3:
        redhat_distribution = distro.linux_distribution()
    else:
        redhat_distribution = platform.linux_distribution()
    logging.debug(
        "Got RHEL Linux distribution " +
        str(redhat_distribution)
    )
    version_string = redhat_distribution[1]
    redhat8 = version_string.startswith("8.")
    # End of RHEL8 out of OS check
    if os_check:
        logging.debug(
            "Going to check the RHEL distribution is supported"
        )
        linux_distribution = check_distribution()
        logging.debug(
            "Got back from check and got Linux distribution " +
            str(linux_distribution)    
        )
        outputfile_dict['linux_distribution'] = linux_distribution
        if linux_distribution in ["redhat", "centos"]:
            logging.debug(
                "We have a RHEL or CentOS distribution. We check for version"
            )
            fatal_error, redhat_distribution_str, redhat8 = check_os_redhat(
                os_dictionary)
            logging.debug(
                "Got back from detailed RHEL check. Got RHEL distribution " +
                redhat_distribution_str +
                ". Detected as RHEL8 is " +
                str(redhat8) +
                ". And fatal_error=" +
                str(fatal_error)
            )
            if fatal_error:
                nfatal_errors = nfatal_errors + 1
            else:
                outputfile_dict['OS'] = redhat_distribution_str
        else:
            logging.debug(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot determine Linux distribution\n"
            )
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " cannot determine Linux distribution\n")
    # Fail if redhat8 + python2
    if toolkit_run:
        if redhat8 and (not PYTHON3):
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " this tool cannot run on RHEL8 and Python 2\n")
    else:
        if redhat8 and (not PYTHON3):
            logging.debug(
                ERROR +
                LOCAL_HOSTNAME +
                " this tool cannot run on RHEL8 and Python 2, " +
                "please check the README\n"
            )
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " this tool cannot run on RHEL8 and Python 2, " +
                "please check the README\n")

    # Check packages
    if packages_ch:
        logging.debug(
            "Going to check for required packages"    
        )
        packages_errors = packages_check(packages_dictionary)
        if packages_errors > 0:
            logging.debug(
                "Got number of failed required packages " +
                str(packages_errors)
            )
            sys.exit(
                ERROR +
                LOCAL_HOSTNAME +
                " has missing packages that need to be installed\n")
        else:
            logging.debug(
                "Passed required packages check"
            )
            outputfile_dict['packages_checked'] = packages_dictionary
    
    # Get node serial number
    logging.debug(
        "Going to get node serial number"
    )
    fatal_error, system_serial = get_system_serial()
    if fatal_error:
        logging.debug(
            "We got an error from quering the system serial"
        )
    else:
        logging.debug(
            "Got node serial number " +
            str(system_serial)
        )
    outputfile_dict['system_serial_error'] = fatal_error
    outputfile_dict['system_serial'] = system_serial
    logging.debug(
        "Wrote serial number on output dictionary"
    )

    # Check memory
    mem_gb = 0
    dimms = 0
    num_dimms = 0
    empty_dimms = 0
    if mem_check:
        logging.debug(
            "Going to perform the memory checks"
        )
        (fatal_error,
            mem_gb,
            dimms,
            num_dimms,
            empty_dimms,
            main_memory_size) = check_memory(min_gb_ram)
        logging.debug(
            "Got memory GB: " +
            str(mem_gb) +
            ". Number of DIMMs: " +
            str(num_dimms) +
            ". Number of empty DIMMs: " +
            str(empty_dimms) +
            ". Main memory size: " +
            str(main_memory_size) +
            ". Fatal error is " +
            str(fatal_error)
        )
        outputfile_dict['memory_all'] = [fatal_error, mem_gb,
                                         dimms, num_dimms, empty_dimms,
                                         main_memory_size]
        outputfile_dict['memory_error'] = fatal_error
        outputfile_dict['system_memory'] = mem_gb
        outputfile_dict['num_dimm_slots'] = num_dimms
        outputfile_dict['num_dimm_empty_slots'] = empty_dimms
        outputfile_dict['dimm_memory_size'] = main_memory_size
        if fatal_error:
            nfatal_errors = nfatal_errors + 1

    # Set SAS_TOOL/SAS_TOOL_ALIAS
    set_sas_tool()

    # Check SAS SAS_adapters
    n_mestor_drives = 0
    n_HDD_drives = 0
    n_SSD_drives = 0
    n_NVME_drives = 0
    SSD_log_home_pres = False
    NVME_log_home_pres = False
    HDD_error = False
    SSD_error = False
    NVME_error = False
    SAS_but_no_usable_drives = False
    NVME_dict = {}
    NVME_ID_dict = {}
    SAS_model = ""
    
    if storage_check:
        logging.debug(
            "Going to perform storage checks"
        )
        if platform.processor() == 's390x':   
            logging.debug(
              "doing NVMe checks on s390x"
            )
            NVME_error, n_NVME_drives = check_NVME()
            logging.debug(
                "Got back from check_NVME with NVME_error=" +
                str(NVME_error) +
                " and n_NVME_drives=" +
                str(n_NVME_drives)
            )
            outputfile_dict['NVME_fatal_error'] = NVME_error
            outputfile_dict['NVME_number_of_drives'] = n_NVME_drives
            if not NVME_error:
                logging.debug(
                    "Going to check for NVMe packages"
                )
                NVME_packages_errors = check_NVME_packages(packages_ch)
                logging.debug(
                    "Got back from check_NVME_packages with NVME_packages_errors=" +
                    str(NVME_packages_errors)
                )
                outputfile_dict['NVME_packages_errors'] = NVME_packages_errors
                if NVME_packages_errors > 0:
                    sys.exit(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has missing packages needed to run this tool\n")
                else:
                    n_mestor_drives = n_mestor_drives + n_NVME_drives
                    logging.debug(
                        "We got " +
                        str(n_NVME_drives) +
                        " NVMe drives. Going to run NVMe checks"
                    )
                    NVME_error, NVME_dict = check_NVME_disks()
                    logging.debug(
                        "Got back from check_NVME_disks with NVME_error=" +
                        str(NVME_error) +
                        " and NVME_dict " +
                        str(NVME_dict)
                    )
            if n_NVME_drives > 0:
                logging.debug(
                    "Going to check WCE on NVMe"
                )
                NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
                outputfile_dict['NVME_WCE_error'] = NVME_WCE_error
                if NVME_WCE_error:
                    nfatal_errors = nfatal_errors + 1
                # All LBA NVME the same check
                logging.debug(
                    "Going to check LBA on NVMe"
                )
                NVME_LBA_error = check_LBA_NVME(NVME_dict)
                logging.debug(
                    "Got back from check_LBA_NVME with NVME_LBA_error=" +
                    str(NVME_LBA_error)
                )
                outputfile_dict['NVME_LBA_error'] = NVME_LBA_error
                if NVME_LBA_error:
                    nfatal_errors = nfatal_errors + 1
                # Metadata NVME check
                logging.debug(
                    "Going to check MD on NVMe"
                )
                NVME_MD_error = check_MD_NVME(NVME_dict)
                logging.debug(
                    "Got back from check_MD_NVME with NVME_MD_error=" +
                    str(NVME_MD_error)
                )
                outputfile_dict['NVME_MD_error'] = NVME_MD_error
                if NVME_MD_error:
                    nfatal_errors = nfatal_errors + 1
            outputfile_dict['NVME_drives'] = NVME_dict

            outputfile_dict['ALL_number_of_drives'] = n_mestor_drives
            # Lets check what we can use here
            if NVME_error:
                logging.debug(
                    "We found issues on SAS and NVMe checks"
                )
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has found issues with NVMe  " +
                    "devices in this system")
                nfatal_errors = nfatal_errors + 1
            else:
                logging.debug(
                    "We have at least one non-rotatioal device in this host"
                )
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has at least one NVMe device that ECE can use. " +
                    "This is required to run ECE")
        else:
            SAS_fatal_error, check_disks, SAS_model = check_SAS(SAS_dictionary)
            logging.debug(
                "Got back from check_SAS with SAS_fatal_error=" +
                str(SAS_fatal_error) +
                ", check_disks=" +
                str(check_disks) +
                " and SAS_model=" +
                str(SAS_model)
            )
            outputfile_dict['error_SAS_card'] = SAS_fatal_error
            outputfile_dict['SAS_model'] = SAS_model
            if check_disks:
                logging.debug(
                    "We have disks to check, first we check the SAS packages"
                )
                SAS_packages_errors = check_SAS_packages(packages_ch)
                logging.debug(
                    "Got SAS_packages_errors=" +
                    str(SAS_packages_errors)
                )
                outputfile_dict['SAS_packages_errors'] = SAS_packages_errors
                if SAS_packages_errors > 0:
                    logging.debug(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has missing packages needed to run this tool\n"
                    )
                    sys.exit(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has missing packages needed to run this tool\n")
                else:
                    logging.debug(
                        "Going to gather more information to add to JSON file"
                    )
                    # Extra information to the JSON
                    logging.debug(
                        "Going to run " + SAS_TOOL + " /call show all j"
                    )
                    call_all = exec_cmd(
                        SAS_TOOL + " /call show all j")
                    logging.debug(call_all)
                    outputfile_dict['storcli_call'] = json.loads(call_all)
                    logging.debug(
                        "Going to run " + SAS_TOOL + " /call/eall show all j"
                    )
                    call_eall_all = exec_cmd(
                        SAS_TOOL + " /call/eall show all j")
                    logging.debug(call_eall_all)
                    outputfile_dict['storcli_call_eall'] = json.loads(call_eall_all)
                    logging.debug(
                        "Going to run " + SAS_TOOL + " /call/eall/sall show all j"
                    )
                    call_sall_all = exec_cmd(
                        SAS_TOOL + " /call/eall/sall show all j")
                    logging.debug(call_sall_all)
                    outputfile_dict['storcli_call_sall_all'] = json.loads(call_sall_all)
                    # Checks start
                    logging.debug(
                        "Going to start HDD tests"
                    )
                    HDD_error, n_HDD_drives, HDD_dict = check_SAS_disks("HDD", sata_on)
                    logging.debug(
                        "Got HDD_error=" +
                        str(HDD_error) +
                        ", and n_HDD_drives=" +
                        str(n_HDD_drives) +
                        ", HDD_dict" +
                        str(HDD_dict)
                    )
                    outputfile_dict['HDD_fatal_error'] = HDD_error
                    outputfile_dict['HDD_n_of_drives'] = n_HDD_drives
                    outputfile_dict['HDD_drives'] = HDD_dict
                    if n_HDD_drives > 0:
                        logging.debug(
                            "Going to check WCE on HDD"
                        )
                        HDD_WCE_error, HDD_dict = check_WCE_SAS(HDD_dict)
                        logging.debug(
                            "Got HDD_WCE_error=" +
                            str(HDD_WCE_error)
                        )
                        outputfile_dict['HDD_WCE_error'] = HDD_WCE_error
                        if HDD_WCE_error:
                            nfatal_errors = nfatal_errors + 1
                    logging.debug(
                        "Going to start SDD tests"
                    )
                    SSD_error, n_SSD_drives, SSD_dict = check_SAS_disks("SSD", sata_on)
                    logging.debug(
                        "Got SSD_error=" +
                        str(SSD_error) +
                        ", and n_SSD_drives=" +
                        str(n_SSD_drives) +
                        ", SSD_dict" +
                        str(SSD_dict)
                    )
                    outputfile_dict['SSD_fatal_error'] = SSD_error
                    outputfile_dict['SSD_n_of_drives'] = n_SSD_drives
                    outputfile_dict['SSD_drives'] = SSD_dict
                    if n_SSD_drives > 0:
                        logging.debug(
                            "Going to check WCE on SSD"
                        )
                        SSD_WCE_error, SSD_dict = check_WCE_SAS(SSD_dict)
                        logging.debug(
                            "Got SSD_WCE_error=" +
                            str(SSD_WCE_error)
                        )
                        outputfile_dict['SSD_WCE_error'] = SSD_WCE_error
                        if SSD_WCE_error:
                            nfatal_errors = nfatal_errors + 1
                        logging.debug(
                            "Going to check for SSD big enough for loghome"
                        )
                        SSD_log_home_pres = check_SSD_loghome(SSD_dict, min_loghome_size)
                        
                    if not HDD_error:
                        n_mestor_drives = n_mestor_drives + n_HDD_drives
                    if not SSD_error:
                        n_mestor_drives = n_mestor_drives + n_SSD_drives
                    logging.debug(
                        "We got " +
                        str(n_HDD_drives) +
                        " HDD and " +
                        str(n_SSD_drives) +
                        " SSD drives that ECE can use"
                    )
                    if HDD_error and SSD_error:
                        logging.debug(
                            "We have a SAS card but no drives ECE can use under it"
                        )
                        SAS_but_no_usable_drives = True
                        outputfile_dict['found_SAS_card_but_no_drives'] = True
            # NVME checks
            logging.debug(
                "Going to start NVMe tests"
            )
            NVME_error, n_NVME_drives = check_NVME()
            logging.debug(
                "Got back from check_NVME with NVME_error=" +
                str(NVME_error) +
                " and n_NVME_drives=" +
                str(n_NVME_drives)
            )
            outputfile_dict['NVME_fatal_error'] = NVME_error
            outputfile_dict['NVME_number_of_drives'] = n_NVME_drives
            if not NVME_error:
                logging.debug(
                    "Going to check for NVMe packages"
                )
                NVME_packages_errors = check_NVME_packages(packages_ch)
                logging.debug(
                    "Got back from check_NVME_packages with NVME_packages_errors=" +
                    str(NVME_packages_errors)
                )
                outputfile_dict['NVME_packages_errors'] = NVME_packages_errors
                if NVME_packages_errors > 0:
                    sys.exit(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has missing packages needed to run this tool\n")
                else:
                    n_mestor_drives = n_mestor_drives + n_NVME_drives
                    logging.debug(
                        "We got " +
                        str(n_NVME_drives) +
                        " NVMe drives. Going to run NVMe checks"
                    )
                    NVME_error, NVME_dict = check_NVME_disks()
                    logging.debug(
                        "Got back from check_NVME_disks with NVME_error=" +
                        str(NVME_error) +
                        " and NVME_dict " +
                        str(NVME_dict)
                    )
            if n_NVME_drives > 0:
                logging.debug(
                    "Going to check WCE on NVMe"
                )
                NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
                logging.debug(
                    "Got back from check_WCE_NVME with NVME_WCE_error=" +
                    str(NVME_WCE_error)
                )
                outputfile_dict['NVME_WCE_error'] = NVME_WCE_error
                if NVME_WCE_error:
                    nfatal_errors = nfatal_errors + 1
                # All LBA NVME the same check
                logging.debug(
                    "Going to check LBA on NVMe"
                )
                NVME_LBA_error = check_LBA_NVME(NVME_dict)
                logging.debug(
                    "Got back from check_LBA_NVME with NVME_LBA_error=" +
                    str(NVME_LBA_error)
                )
                outputfile_dict['NVME_LBA_error'] = NVME_LBA_error
                if NVME_LBA_error:
                    nfatal_errors = nfatal_errors + 1
                # Metadata NVME check
                logging.debug(
                    "Going to check MD on NVMe"
                )
                NVME_MD_error = check_MD_NVME(NVME_dict)
                logging.debug(
                    "Got back from check_MD_NVME with NVME_MD_error=" +
                    str(NVME_MD_error)
                )
                outputfile_dict['NVME_MD_error'] = NVME_MD_error
                if NVME_MD_error:
                    nfatal_errors = nfatal_errors + 1
                                #check nguid and euid of nvmes drives for uniqueness
                logging.debug(
                    "Going to check NVMe ID uniqueness"
                )
                NVME_DUPLICATE_ID_error, NVME_ID_dict = check_NVME_ID(NVME_dict)
                logging.debug(
                    "Got back from check_NVME_ID with NVME_DUPLICATE_ID_error=" +
                    str(NVME_DUPLICATE_ID_error) +
                    " and NVME_ID_dict=" +
                    str(NVME_ID_dict)
                )
                outputfile_dict['NVME_DUPLICATE_ID_error'] = NVME_DUPLICATE_ID_error

                if NVME_DUPLICATE_ID_error:
                    nfatal_errors = nfatal_errors + 1
                    
                logging.debug(
                    "Going to check for NVMe big enough for loghome"
                )
                NVME_log_home_pres = check_NVME_log_home(NVME_dict, min_loghome_size)
                
            loghome_pres = NVME_log_home_pres or SSD_log_home_pres
            if not loghome_pres:
                print(
                    ERROR + 
                    LOCAL_HOSTNAME +
                    " does not have NVMe or SSD drive with at least "
                    + str(min_loghome_size) + " bytes of storage" )
                nfatal_errors = nfatal_errors + 1
            
            outputfile_dict['NVME_drives'] = NVME_dict
            outputfile_dict['NVME_ID'] = NVME_ID_dict
            outputfile_dict['loghome_error'] = not loghome_pres

            logging.debug(
                "the number of drives ECE can use in this host is " +
                str(n_mestor_drives)
            )
            outputfile_dict['ALL_number_of_drives'] = n_mestor_drives
            # Throw a warning if no drives
            if SAS_but_no_usable_drives:
                logging.debug(
                    "We have a supported SAS card but no usable drives"
                )
                print(
                    WARNING +
                    LOCAL_HOSTNAME +
                    " has a supported SAS adapter but no supported drives")
            # Lets check what we can use here
            if SAS_fatal_error and NVME_error:
                logging.debug(
                    "We found issues on SAS and NVMe checks"
                )
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has found issues with SAS adapter and NVMe  " +
                    "devices in this system")
                nfatal_errors = nfatal_errors + 1
            if SSD_error and NVME_error:
                logging.debug(
                    "There is no non-rotational device in this host"
                )
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has no SSD or NVMe device that ECE can use. At least " +
                    "one device of those types is required to run ECE")
                nfatal_errors = nfatal_errors + 1
            else:
                logging.debug(
                    "We have at least one non-rotatioal device in this host"
                )
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " has at least one SSD or NVMe device that ECE can use. " +
                    "This is required to run ECE")
                if n_mestor_drives > max_drives:
                    logging.debug(
                        "This host has " +
                        str(n_mestor_drives) +
                        " drives which is more than the allowed max of " +
                        str(max_drives) +
                        " per host"
                    )
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has more than " +
                        str(max_drives) +
                        " drives that ECE can use in one RG. " +
                        "This is not supported by ECE")
                    nfatal_errors = nfatal_errors + 1
                else:
                    print(
                        INFO +
                        LOCAL_HOSTNAME +
                        " has " +
                        str(n_mestor_drives) +
                        " drives that ECE can use")

    # Network checks
    logging.debug(
        "Going to start network checks on this host: " +
        LOCAL_HOSTNAME
    )
    outputfile_dict['local_hostname'] = LOCAL_HOSTNAME
    ip_address_is_IP = is_IP_address(ip_address)
    logging.debug(
        "The input IP address is possible?=" +
        str(ip_address_is_IP)
    )
    outputfile_dict['IP_address_is_possible'] = ip_address_is_IP
    outputfile_dict['ip_address'] = ip_address
    NIC_model = ""
    device_speed = "NOT CHECKED"

    if net_check:
        logging.debug(
            "Going to check NIC model"
        )
        fatal_error, NIC_model = check_NIC(NIC_dictionary,ip_address)
        logging.debug(
            "Got back from check_NIC with fatal_error=" +
            str(fatal_error) +
            " and NIC_model=" +
            str(NIC_model)
        )
        outputfile_dict['error_NIC_card'] = fatal_error
        outputfile_dict['NIC_model'] = NIC_model
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
        elif (ip_address_is_IP):
            logging.debug(
                "Going to check if IP corresponds to a device what its link speed"
            )
            print(
                INFO +
                LOCAL_HOSTNAME +
                " checking " +
                ip_address +
                " device and link speed")
            net_devices = list_net_devices()
            outputfile_dict['ALL_net_devices'] = net_devices
            fatal_error, net_interface = what_interface_has_ip(
                net_devices, ip_address)
            logging.debug(
                "Got back from what_interface_has_ip with fatal_error=" +
                str(fatal_error) +
                " and net_interface=" +
                str(net_interface)
            )
            outputfile_dict['IP_not_found'] = fatal_error
            outputfile_dict['netdev_with_IP'] = net_interface
            if fatal_error:
                nfatal_errors = nfatal_errors + 1
            else:
                # It is a valid IP and there is an interface on this node with
                # this IP
                fatal_error, device_speed = check_NIC_speed(
                    net_interface, min_link_speed)
                logging.debug(
                    "Got back from check_NIC_speed with fatal_error=" +
                    str(fatal_error) +
                    " and link speed of " +
                    str(device_speed)
                )
                outputfile_dict['netdev_speed_error'] = fatal_error
                outputfile_dict['netdev_speed'] = device_speed
                if fatal_error:
                    nfatal_errors = nfatal_errors + 1
        else:
            logging.debug(
                "The IP is not a valid one"
            )
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " " +
                ip_address +
                " is not a valid IP address")
            nfatal_errors = nfatal_errors + 1

    # Check tuned
    if tuned_check:
        logging.debug(
            "Going to check tuned profile"
        )
        fatal_error = tuned_adm_check()
        logging.debug(
            "Got back from tuned_adm_check with fatal_error=" +
            str(fatal_error)
        )
        if fatal_error:
            nfatal_errors = nfatal_errors + 1
            outputfile_dict['tuned_fail'] = True
        else:
            outputfile_dict['tuned_fail'] = False

    # Check py3 YAML
    logging.debug(
        "Going to check for py3_yaml"
    )
    fatal_error = check_py3_yaml()
    logging.debug(
        "Got back from check_py3_yaml with fatal_error=" +
        str(fatal_error)
    )
    if fatal_error:
        nfatal_errors = nfatal_errors + 1
        outputfile_dict['py3_yaml_fail'] = True
    else:
        outputfile_dict['py3_yaml_fail'] = False
    
    # Set general status of acceptance of this node
    if nfatal_errors == 0 and all_checks_on:
        logging.debug(
            "All checks were enabled and were passed successfully"
        )
        outputfile_dict['ECE_node_ready'] = True
    else:
        logging.debug(
            "Either not all checks were enabled or not all were passed successfully"
        )
        outputfile_dict['ECE_node_ready'] = False

    # Save lspci output to JSON
    lspci_dict = dict()
    lspci_output = exec_cmd("lspci")
    if not PYTHON3:
        for line in lspci_output.splitlines():
            try:
                pcimatch = PCIPATT.match(line)
                key = pcimatch.group('pciaddr')
                value = pcimatch.group('pcival')
                lspci_dict[key] = value
                # continue if we can't parse lspci data
                # this data is saved best effort only
            except Exception:
                continue
    else:
        lspci_dict["python3"] = True

    outputfile_dict['lspci'] = lspci_dict

    # Exit protocol    
    DEVNULL.close()

    outputfile_name = path + ip_address + ".json"
    end_time_date = datetime.datetime.now()
    outputfile_dict['end_time'] = str(end_time_date)
    outputdata = json.dumps(str(outputfile_dict), sort_keys=True, indent=4,
                            separators=(',', ': '))
    with open(outputfile_name, "w") as outputfile:
        outputfile.write(outputdata)

    if toolkit_run and nfatal_errors > 0:
        print_summary_toolkit()
    if toolkit_run is False:
        print_summary_standalone(
            nfatal_errors,
            outputfile_name,
            start_time_date,
            end_time_date,
            redhat_distribution_str,
            current_processor,
            num_sockets,
            core_count,
            mem_gb,
            num_dimms,
            empty_dimms,
            SAS_model,
            n_HDD_drives,
            n_SSD_drives,
            n_NVME_drives,
            NIC_model,
            device_speed,
            all_checks_on,
            sata_on)


if __name__ == '__main__':
    main()

