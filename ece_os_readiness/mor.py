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

if PYTHON3 is False:
    import commands


# Start the clock
start_time_date = datetime.datetime.now()

# This script version, independent from the JSON versions
MOR_VERSION = "1.80"

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
NIC_ADAPTERS_MD5 = "dca06f75452f45c65658660fb8e969e6"
PACKAGES_MD5 = "a15b08b05998d455aad792ef5d3cc811"
SAS_ADAPTERS_MD5 = "42f27f9179992928ebbc6e3becc79ba6"
SUPPORTED_OS_MD5 = "9f519023ac0e072bffab4e98d36cb984"

# acceptable speed of SCSI controller
ACC_CTRLR_SPEED = '12G'

COMPATIBLE_TUNEDS = [
    'spectrumscale-ece',
    'storagescale-ece'
]

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
        help='To indicate is being run from IBM Storage Scale install toolkit',
        default=False)

    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version='IBM Storage Scale Erasure Code Edition OS readiness ' +
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


    print("{0}{1} has SAS TOOL: {2}".format(INFO, LOCAL_HOSTNAME, SAS_TOOL))
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
    """
    Params:
        size - digit
        unit - unit of size
    Returns:
        Directly exits if hit fatal error
        size_in_bytes - Convert size and unit to size in bytes
    """
    if size and isinstance(size, int):
        pass
    else:
        sys.exit("{0}{1} invalid parameter size({2})".
            format(ERROR, LOCAL_HOSTNAME, size))

    if unit and isinstance(unit, str) and \
       unit in ('KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB'):
        pass
    else:
        sys.exit("{0}{1} invalid parameter unit({2})".
            format(ERROR, LOCAL_HOSTNAME, size))

    unit_dict = {"KB":10**3, "MB":10**6,"GB":10**9, "TB":10**12,
                 "KiB":2**10, "MiB":2**20, "GiB":2**30, "TiB": 2**40}

    size_in_bytes = -1
    if unit in unit_dict.keys():
        # Would not hit KeyError here. unit is well checked
        size_in_bytes = size * unit_dict[unit]

    return size_in_bytes


def show_header(moh_version, json_version, toolkit_run):
    print(
        INFO +
        LOCAL_HOSTNAME +
        " IBM Storage Scale Erasure Code Edition OS readiness version " +
        moh_version)
    if not toolkit_run:
        print("{0}{1} There is absolutely no warranty on ".format(INFO,
              LOCAL_HOSTNAME) + "this precheck tool")
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


def run_shell_cmd(cmd, ignore_exception=False):
    """
    Params:
        cmd: command string.
        ignore_exception: [Optional] default is False.
                          False, print message and exit if hit exception.
                          True, translate exception to string and push it to stderr.
    Returns:
        (stdout, stderr, returncode)
    """
    if not cmd or isinstance(cmd, str) is False:
        if ignore_exception is True:
            return '', "Invalid cmd: {}".format(cmd), 1
        else:
            sys.exit("{0}{1} Invalid parameter cmd: {2}".format(ERROR,
                     LOCAL_HOSTNAME, cmd))
    try:
        proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=None)
        stdout, stderr = proc.communicate()
        rc = proc.returncode
    except BaseException as e:
        if ignore_exception is True:
            return '', "{}".format(e), 1
        else:
            sys.exit("{0}{1} tried to run cmd: '{2}' but ".format(ERROR,
                     LOCAL_HOSTNAME, cmd) + "hit exception: {}".format(e))

    if isinstance(stdout, bytes):
        stdout = stdout.decode()
    if isinstance(stderr, bytes):
        stderr = stderr.decode()

    return str(stdout), str(stderr), int(rc)


def is_pkg_installed(rpm_package):
    """
    Params:
        rpm_package - Keyword of package to be checked
    Returns:
        0 if package is installed, else,
        1
    """
    if rpm_package:
        if isinstance(rpm_package, str) or isinstance(rpm_package, unicode):
            pass
        else:
            sys.exit("{0}{1} invalid parameter rpm_package({2})".
                format(ERROR, LOCAL_HOSTNAME, rpm_package))
    else:
        sys.exit("{0}{1} empty parameter rpm_package".
            format(ERROR, LOCAL_HOSTNAME))

    cmd = "rpm -q {}".format(rpm_package)
    _, _, rc = run_shell_cmd(cmd)
    return rc


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


def is_ipv4(ipv4):
    """
    Params:
        ipv4 - Standard IPv4 format
    Returns:
        bool - True if yes, else, False
    """
    if not ipv4 or isinstance(ipv4, str) is False:
        sys.exit("{0}{1} invalid parameter: ipv4".format(ERROR,
                 LOCAL_HOSTNAME))

    ipv4_seg_list = ipv4.split('.')
    ipv4_seg_num = len(ipv4_seg_list)
    if ipv4_seg_num != 4:
        print("{0}{1} segment number({2}) of dotted IPv4({3}) is invalid".
            format(ERROR, LOCAL_HOSTNAME, ipv4_seg_num, ipv4))
        return False

    for seg in ipv4_seg_list:
        if not seg.isdigit():
            print("{0}{1} segment({2}) in IPv4({3}) is non-numeric".
                format(ERROR, LOCAL_HOSTNAME, seg, ipv4))
            return False
        try:
            digit_seg = int(seg)
        except ValueError as e:
            sys.exit("{0}{1} tried to convert segment({2}). Hit ".
                format(ERROR, LOCAL_HOSTNAME, seg) + "ValueError: {}".
                format(e))
        if digit_seg < 0 or digit_seg > 255:
            print("{0}{1} segment({2}) in IPv4({3}) is invalid".
                format(ERROR, LOCAL_HOSTNAME, seg, ipv4))
            return False

    return True


def map_ipv4_to_local_interface(ipv4):
    """
    Params:
        ipv4 - Standard IPv4 format
    Returns:
        Directly exits if hit fatal error
        ipv4_dict -
            If mapped successfully:
                {'IPv4': 'local active network interface'}
            else:
                {'IPv4': ''}
    """
    if ipv4 and isinstance(ipv4, str):
        pass
    else:
        sys.exit("{0}{1} invalid parameter ipv4({2})".
            format(ERROR, LOCAL_HOSTNAME, ipv4))

    ipv4_dict = {}
    is_ipv4_ok = is_ipv4(ipv4)
    if not is_ipv4_ok:
        sys.exit("{0}{1} invalid ipv4({2}) format".
            format(ERROR, LOCAL_HOSTNAME, ipv4))

    try:
        active_dev_list = ethtool.get_active_devices()
    except BaseException as e:
        sys.exit("{0}{1} tried to query active network device. Hit ".
            format(ERROR, LOCAL_HOSTNAME) + "exception: {}".format(e))

    if not active_dev_list:
        sys.exit("{0}{1} no active network device found".
            format(ERROR, LOCAL_HOSTNAME))

    for dev in active_dev_list:
        try:
            ip_of_dev = ethtool.get_ipaddr(dev)
        except BaseException as e:
            logging.debug("Tried to get ipaddr but hit exception: %s", e)
            continue
        if ip_of_dev == ipv4:
            ipv4_dict[ipv4] = dev

    if not ipv4_dict:
        print("{0}{1} has no IP {2} set to local active network device".
            format(ERROR, LOCAL_HOSTNAME, ipv4))
        ipv4_dict[ipv4] = ''

    return ipv4_dict


def map_netif_to_product():
    """
    Params:
    Returns:
        Directly exits if hit fatal error
        netif_dict - {
            'network interface logical name 0': 'product name 0',
            'network interface logical name 1': 'product name 1',
            ...
        }
    """
    cmd = "lshw -class network -quiet"
    cmd_out, _, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    if not cmd_out:
        sys.exit("{0}{1} got nothing by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))

    lshw_out_lines = cmd_out.splitlines()
    reversed_lshw_lines = list(reversed(lshw_out_lines))
    netif_dict = {}
    if_key = ''
    for line in reversed_lshw_lines:
        line = line.strip()
        # Refresh product_str for each interation
        product_str = ''
        if 'logical name:' in line:
            try:
                if_key = line.split()[-1].strip()
            except BaseException as e:
                print("{0}{1} tried to extract network logical name ".
                    format(WARNING, LOCAL_HOSTNAME) +
                    "form {0}. Hit exception: {1}".format(line, e))
        if not if_key:
            # Skip if got empty logical name
            continue
        if 'product:' in line:
            try:
                product_str = line.split('product:')[-1].strip()
            except BaseException as e:
                print("{0}{1} tried to extract product name from {2}.".
                    format(WARNING, LOCAL_HOSTNAME, line) +
                    "Hit exception: {}".format(e))
        if not product_str:
            # Skip if got empty product name
            continue
        netif_dict[if_key] = product_str

    if not netif_dict:
        print("{0}{1} failed to map logical-name to product-name ".
            format(ERROR, LOCAL_HOSTNAME) + "for network interface")

    return netif_dict


def get_network_interface_speed(
        if_name,
        min_link_speed):
    """
    Params:
        if_name: network interface name.
        min_link_speed: minimum port speed in Mb/s.
    Returns:
        (fatal_error, speed)
    """
    if not if_name or isinstance(if_name, str) is False:
        print("{0}{1} invalid parameter: if_name".format(ERROR,
              LOCAL_HOSTNAME))
        return True, 0
    if not min_link_speed or isinstance(min_link_speed, int) is False:
        print("{0}{1} invalid parameter: min_link_speed".format(ERROR,
              LOCAL_HOSTNAME))
        return True, 0

    cmd = "ethtool {}".format(if_name)
    out, err, rc = run_shell_cmd(cmd)
    out = out.strip()
    err = err.strip()
    if rc != 0 or not out:
        print("{0}{1} ran cmd: '{2}'".format(ERROR, LOCAL_HOSTNAME, cmd))
        if err:
            print("{0}{1} hit error:\n{2}".format(ERROR, LOCAL_HOSTNAME,
                  err))
        if not out:
            print("{0}{1} got nothing".format(ERROR, LOCAL_HOSTNAME))
        return True, 0

    speed = 0
    fatal_error = False
    out_lines = out.splitlines()
    for line in out_lines:
        if 'Speed:' not in line:
            continue
        try:
            line_to_list = line.split()
            raw_speed = line_to_list[-1].strip()
            raw_speed_to_list = raw_speed.split('Mb/s')
            speed = int(raw_speed_to_list[0])
        except BaseException as e:
            print("{0}{1} tried to extract speed of network ".format(ERROR,
                  LOCAL_HOSTNAME) + "interface {} but ".format(if_name) +
                  "exception: {}".format(e))
            return True, 0
    if speed == 0:
        fatal_error = True
        print("{0}{1} failed to extract speed of network ".format(ERROR,
              LOCAL_HOSTNAME) + "interface {}".format(if_name))
        return True, 0
    elif speed >= min_link_speed:
        print("{0}{1} has {2} with {3} Mb/s speed can be ".format(INFO,
              LOCAL_HOSTNAME, if_name, speed) + "used by ECE")
    else:
        fatal_error = True
        print("{0}{1} has {2} with {3} Mb/s speed which is ".format(ERROR,
              LOCAL_HOSTNAME, if_name, speed) + "less than ECE required")
    return fatal_error, speed


def check_root_user():
    """
    Params:
    Returns:
        0 if current user is root.
        exit if current is not root.
    """
    effective_uid = os.getuid()
    if effective_uid == 0:
        print("{0}{1} current user is root".format(INFO, LOCAL_HOSTNAME))
        return 0
    else:
        sys.exit("{0}{1} this tool needs to be run under ".format(ERROR,
                 LOCAL_HOSTNAME) + "root\n")


def check_vmware_nic(
        ip_if_dict,
        net_check,
        supported_nic_dict,
        min_link_speed):
    """
    Params:
        ip_if_dict: {'IPv4': 'local active network interface'}.
        net_check: True if network checking is required, else, False.
        supported_nic_dict: supported NIC in NIC_adapters.json.
        min_link_speed: MIN_LINK_SPEED in HW_requirements.json.
    Returns:
        (error_count, outputfile_segment_dict)
        exit if hit fatal error.
    Remarks:
        Simulate physical checking.
        At present, this function does not support network with bond, RDMA, RoCE.
    """
    if ip_if_dict and isinstance(ip_if_dict, dict) and len(ip_if_dict) == 1:
        pass
    else:
        sys.exit("{0}{1} invalid parameter ip_if_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, ip_if_dict))

    if net_check and isinstance(net_check, bool):
        pass
    else:
        sys.exit("{0}{1} invalid parameter net_check({2})".
            format(ERROR, LOCAL_HOSTNAME, net_check))

    if supported_nic_dict and isinstance(supported_nic_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter supported_nic_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, supported_nic_dict))

    if min_link_speed and isinstance(min_link_speed, int):
        pass
    else:
        sys.exit("{0}{1} invalid parameter min_link_speed({2})".
            format(ERROR, LOCAL_HOSTNAME, min_link_speed))

    outputfile_segment_dict = {}
    outputfile_segment_dict['local_hostname'] = LOCAL_HOSTNAME

    error_count = 0
    ip_addr = ''
    netif_with_ip = ''
    for key, val in ip_if_dict.items():
        ip_addr = key
        netif_with_ip = val
    logging.debug("From ip_if_dict, Got netif_with_ip=%s", netif_with_ip)

    if not ip_addr:
        error_count += 1
        outputfile_segment_dict['IP_address_is_possible'] = False
        outputfile_segment_dict['ip_address'] = ''
        outputfile_segment_dict['IP_not_found'] = True
        print("{0}{1} cannot extract IP address from {2}".
            format(ERROR, LOCAL_HOSTNAME, ip_if_dict))
    else:
        outputfile_segment_dict['IP_address_is_possible'] = True
        outputfile_segment_dict['ip_address'] = ip_addr
        outputfile_segment_dict['IP_not_found'] = False

    if not net_check:
        return error_count, outputfile_segment_dict

    print("{0}{1} checking NIC".format(INFO, LOCAL_HOSTNAME))

    if not netif_with_ip:
        error_count += 1
        outputfile_segment_dict['error_NIC_card'] = True
        outputfile_segment_dict['NIC_model'] = []
        outputfile_segment_dict['netdev_with_IP'] = ''
        print("{0}{1} cannot extract logical network interface of {2}".
            format(ERROR, LOCAL_HOSTNAME, ip_addr))
    else:
        outputfile_segment_dict['netdev_with_IP'] = netif_with_ip

    all_netif_list = []
    nic_product_name = ''
    ok_nic_product_list = []
    netif_dict = map_netif_to_product()
    logging.debug("Called map_netif_to_product, got netif_dict=%s", netif_dict)
    if netif_dict:
        all_netif_list = [key for key in netif_dict]

    logging.debug("From netif_dict, Got all_netif_list=%s", all_netif_list)
    if not all_netif_list:
        error_count += 1
        outputfile_segment_dict['ALL_net_devices'] = []
        print("{0}{1} cannot extract any network device".
            format(ERROR, LOCAL_HOSTNAME))
    else:
        # Implies netif_dict is existed
        outputfile_segment_dict['ALL_net_devices'] = all_netif_list
        if netif_with_ip:
            try:
                nic_product_name = netif_dict[netif_with_ip]
            except KeyError as e:
                error_count += 1
                print("{0}{1} tried to extract product name of {2}. Hit ".
                    format(ERROR, LOCAL_HOSTNAME, netif_with_ip) +
                    "KeyError: {}".format(e))

            if not nic_product_name:
                error_count += 1
                outputfile_segment_dict['error_NIC_card'] = True
                outputfile_segment_dict['NIC_model'] = []
                print("{0}{1} cannot extract any proper NIC product name".
                    format(ERROR, LOCAL_HOSTNAME))
        logging.debug("From netif_dict, Got nic_product_name=%s", nic_product_name)

    if nic_product_name:
        ok_nic_product_list = \
            [nic_product_name for key in supported_nic_dict if key in nic_product_name]
    logging.debug("From supported_nic_dict=%s, got ok_nic_product_list=%s",
        supported_nic_dict, ok_nic_product_list)

    if not ok_nic_product_list:
        outputfile_segment_dict['error_NIC_card'] = True
        outputfile_segment_dict['NIC_model'] = []
        print("{0}{1} has no supported NIC that can be used by ECE".
            format(ERROR, LOCAL_HOSTNAME))
    else:
        outputfile_segment_dict['error_NIC_card'] = False
        outputfile_segment_dict['NIC_model'] = ok_nic_product_list
        print("{0}{1} has {2} which can be used by ECE".format(INFO,
              LOCAL_HOSTNAME, ", ".join(ok_nic_product_list)))

    if netif_with_ip:
        netif_speed_err, netif_speed = \
            get_network_interface_speed(netif_with_ip, min_link_speed)
        logging.debug("Called get_network_interface_speed, Got netif_speed_err=%s, netif_speed=%s",
                      netif_speed_err, netif_speed)
        outputfile_segment_dict['netdev_speed_error'] = netif_speed_err
        outputfile_segment_dict['netdev_speed'] = netif_speed
        if netif_speed_err:
            error_count += 1
    else:
        error_count += 1
        outputfile_segment_dict['netdev_speed_error'] = True
        outputfile_segment_dict['netdev_speed'] = 'NOT CHECKED'

    return error_count, outputfile_segment_dict


def package_check(pkg_dict):
    """
    Params:
        pkg_dict - {'keyword': expected_return_code}
    Returns:
        error_count - count of error
    """
    if pkg_dict and isinstance(pkg_dict, dict):
        pass
    else:
        print("{0}{1} invalid parameter pkg_dict".format(ERROR,
              LOCAL_HOSTNAME))
        return 1

    #print("{0}{1} is checking package installation status".format(INFO,
    #      LOCAL_HOSTNAME))

    error_count = 0
    for package in pkg_dict.keys():
        if platform.processor() == 's390x' and package == 'dmidecode':
            continue
        if package == "json_version":
            continue
        current_package_rc = is_pkg_installed(package)
        inst_stat = ''
        if current_package_rc == 0:
            inst_stat = "has {} installed".format(package)
        else:
            inst_stat = "does not have {} installed".format(package)
        expected_package_rc = pkg_dict[package]
        if current_package_rc == expected_package_rc:
            print("{0}{1} {2} as expected".format(INFO, LOCAL_HOSTNAME,
                  inst_stat))
        else:
            print("{0}{1} {2} is *NOT* as expected".format(ERROR,
                  LOCAL_HOSTNAME, inst_stat))
            error_count += 1

    return error_count


def get_system_serial():
    # For now we do OS call, not standarized output on python dmidecode
    fatal_error = False
    system_serial = "00000000"
    if platform.processor() == 's390x':  # No serial# checking on s390x
        return fatal_error, system_serial
    try:
        if PYTHON3:
            system_serial = subprocess.getoutput(
                "dmidecode -s system-serial-number")
        else:
            system_serial = commands.getoutput(
                "dmidecode -s system-serial-number")
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query system serial")
    return fatal_error, system_serial


def check_processor():
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " is checking processor compatibility")
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


def detect_virtualization():
    """
    Params:
    Returns:
        'error' - if hit error
        output of command: systemd-detect-virt
        'vmware' - if OS was running on VMware
        'none' - if OS was running on physical machine
        ...
    """
    cmd = 'systemd-detect-virt'
    virt_type, err, _ = run_shell_cmd(cmd)
    virt_type = virt_type.strip()
    err = err.strip()
    if err:
        print("{0}{1} executed cmd: {2}. Got stderr: {3}".
            format(ERROR, LOCAL_HOSTNAME, cmd, err))
        return 'error'
    if not virt_type:
        print("{0}{1} cannot detect the virtualized environment by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))
        return 'error'

    if virt_type == 'none':
        # Physical environment
        pass
    elif virt_type == 'vmware':
        product = ''
        get_product_name_cmd = 'cat /sys/class/dmi/id/product_name'
        product, _, _ = run_shell_cmd(get_product_name_cmd, True)
        product = product.strip()
        if product:
            print("{0}{1} is virtual machine running on {2}".
                format(INFO, LOCAL_HOSTNAME, product))
    else:
        print("{0}{1} is virtual machine running on virtualized environment({2}) ".
            format(ERROR, LOCAL_HOSTNAME, virt_type) +
            "which is not verified to support ECE")

    return virt_type


def get_cpu_socket_core_num_by_lscpu():
    """
    Params:
    Returns:
        (socket_num, total_core_num, core_list)
        socket_num - int
        total_core_num - int
        core_list - list
    """
    cmd = 'lscpu'
    socket_num = 0
    core_list = []

    cmd_out, err, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    err = err.strip()
    if err:
        print("{0}{1} queried socket or core information by running cmd: {2}. ".
            format(ERROR, LOCAL_HOSTNAME, cmd) +
            "Hit error: {}".format(err))
        return 0, 0, []
    if not cmd_out:
        print("{0}{1} got empty socket or core information by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))
        return 0, 0, []

    out_lines = cmd_out.splitlines()
    core_per_socket = 0
    for line in out_lines:
        if 'Socket(s):' in line:
            try:
                socket_num = int(line.split()[-1])
            except BaseException as e:
                print("{0}{1} tried to extract socket number. Hit exception: {2}".
                    format(ERROR, LOCAL_HOSTNAME, e))
                return 0, 0, []
            if socket_num < 1:
                print("{0}{1} got invalid socket number {2} by running cmd: {3}".
                    format(ERROR, LOCAL_HOSTNAME, socket_num, cmd))
                return 0, 0, []

        if 'Core(s) per socket:' in line:
            try:
                core_per_socket = int(line.split()[-1])
            except BaseException as e:
                print("{0}{1} cannot extract number of core per socket. ".
                    format(ERROR, LOCAL_HOSTNAME) + "Hit exception: {}".
                    format(e))
                return socket_num, 0, []
            if core_per_socket < 1:
                print("{0}{1} got invalid core-per-socket {2} by running cmd: ".
                    format(ERROR, LOCAL_HOSTNAME, core_per_socket) +
                    "{}".format(cmd))
                return socket_num, 0, []

    # Keyword 'Socket(s):' is not in output of lscpu
    if socket_num < 1:
        print("{0}{1} cannot extract socket number by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))
        return 0, 0, []

    # Keyword 'Core(s) per socket:' is not in output of lscpu
    if core_per_socket < 1:
        print("{0}{1} cannot extract core-per-socket by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))
        return socket_num, 0, []

    total_core_num = socket_num * core_per_socket
    core_list.append(core_per_socket)
    core_list *= socket_num

    return socket_num, total_core_num, core_list


def check_sockets_cores(min_socket, min_cores):
    fatal_error = False
    cores = []
    num_sockets = 0
    virt_type = detect_virtualization()
    logging.debug("Called detect_virtualization, got virt_type=%s", virt_type)
    if virt_type not in ('vmware', 'none'):
        sys.exit(1)
    if platform.processor() != 's390x' and virt_type == 'none':
        print(INFO + LOCAL_HOSTNAME + " is checking socket count")
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

    print(INFO + LOCAL_HOSTNAME + " is checking core count")
    if platform.processor() == 's390x':
        cores =  core_count = multiprocessing.cpu_count()
        core_count = int(multiprocessing.cpu_count())
        cores.append(core_count)
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
        if virt_type == 'none':
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
            if total_core_num < 1:
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " has a total of " +
                    str(total_core_num) +
                    " core which cannot run ECE")
                fatal_error = True
            elif total_core_num < min_cores:
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
        # virt_type == 'error' and virt_type == 'other' has been returned
        elif virt_type == 'vmware':
            num_sockets, total_core_num, cores = get_cpu_socket_core_num_by_lscpu()
            if not cores:
                fatal_error = True
            if total_core_num < 1:
                print("{0}{1} has a total of {2} virtual core which cannot run ECE".
                    format(ERROR, LOCAL_HOSTNAME, total_core_num))
                fatal_error = True
            elif total_core_num < min_cores:
                print("{0}{1} has a total of {2} virtual core[s] which is less ".
                    format(WARNING, LOCAL_HOSTNAME, total_core_num) +
                    "than {} cores required to run ECE".format(min_cores))
            else:
                print("{0}{1} has a total of {2} virtual cores which complies ".
                    format(INFO, LOCAL_HOSTNAME, total_core_num) +
                    "with the requirements to support ECE")

    return fatal_error, num_sockets, cores


def check_memory(min_gb_ram):
    fatal_error = False
    print(INFO + LOCAL_HOSTNAME + " is checking memory")
    # Total memory
    if platform.processor() == 's390x':
        meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) \
            for i in open('/proc/meminfo').readlines())
        mem_kib = meminfo['MemTotal']  # e.g. 3921852
        mem_gb  = round(mem_kib / 1024 / 1024, 2)
    else:
        mem_b = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        mem_gb = mem_b / 1024**3
        mem_gb = round(mem_gb, 2)
    if mem_gb < min_gb_ram:
        print("{0}{1} has a total of {2} GiB memory which ".format(ERROR,
              LOCAL_HOSTNAME, mem_gb) + "is less than {} GiB ".format(
              min_gb_ram) + "required to run ECE")
        fatal_error = True
    else:
        print("{0}{1} has a total of {2} GiB memory which ".format(INFO,
              LOCAL_HOSTNAME, mem_gb) + "is sufficient to run ECE")
    # Memory DIMMs
    if platform.processor() == 's390x':    # no dims on s390x
        dimm_dict = {}
        dimm_num = 0
        empty_dimm_slot_count = 0
        dedup_dimm_size_list = []
    else:
        dimm_dict = {}
        dimm_num = 0
        empty_dimm_slot_count = 0
        valid_dim_dict = {}
        mem_slot_dict = dmidecode.memory()
        if not mem_slot_dict:
            print("{0}{1} got empty memory slot dictionary ".format(ERROR,
                  LOCAL_HOSTNAME) + "by dmidecode")
            fatal_error = True
        for val in mem_slot_dict.values():
            # Avoiding 'System Board Or Motherboard'. Need more data
            if val['data']['Error Information Handle'] == 'Not Provided':
                continue

            try:
                locator = val['data']['Locator']
                loc_size = val['data']['Size']
            except KeyError as e:
                logging.debug("Extract DIMM locator or size. Hit KeyError: %s", e)
                continue

            if isinstance(locator, bytes):
                locator = locator.decode()
            if isinstance(loc_size, bytes):
                loc_size = loc_size.decode()
            if not locator:
                logging.debug("Got empty DIMM Locator from %s", val)
                continue
            if not loc_size:
                logging.debug("Got empty DIMM size from %s", val)

            dimm_dict[locator] = loc_size
            if loc_size is None or 'NO DIMM' == loc_size:
                empty_dimm_slot_count += 1
            else:
                valid_dim_dict[locator] = loc_size

        dimm_num = len(dimm_dict)
        populated_dimm_num = len(valid_dim_dict)
        if dimm_num < 1:
            print("{0}{1} generate empty DIMM dictionary from ".format(ERROR,
                  LOCAL_HOSTNAME) + "dmidecode")
            fatal_error = True
        else:
            if empty_dimm_slot_count > 0:
                print("{0}{1} has {2}({3} in total) DIMM slot[s] ".format(WARNING,
                      LOCAL_HOSTNAME, populated_dimm_num, dimm_num) + "which " +
                      "is not optimal when NVMe drive was used")
            else:
                print("{0}{1} has a total of {2} DIMM slot[s] which ".format(
                      INFO, LOCAL_HOSTNAME, dimm_num) + "is fully populated")

            dimm_size_list = valid_dim_dict.values()
            try:
                dedup_dimm_size_list = list(set(dimm_size_list))
            except TypeError as e:
                print("{0}{1} tried to deduplicate DIMM size but ".format(ERROR,
                      LOCAL_HOSTNAME) + "hit TypeError: {}".format(e))
                fatal_error = True

            if len(dedup_dimm_size_list) == 1:
                print("{0}{1} all populated DIMM slots have same size".format(INFO,
                      LOCAL_HOSTNAME))
            else:
                print("{0}{1} not all populated DIMM slots have same size".format(
                      ERROR, LOCAL_HOSTNAME))
                fatal_error = True

    return fatal_error, mem_gb, dimm_dict, dimm_num, empty_dimm_slot_count, \
           dedup_dimm_size_list


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
    except AttributeError:
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
                " See IBM Storage Scale FAQ for restrictions.")
        else:
            sys.exit(error_message)

    except BaseException:
        sys.exit(error_message)

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


def get_nvme_drive_num():
    """
    Params:
    Returns:
        fatal_error: False if error occurred, else, True.
        nvme_drive_num: number of NVMe drive.
    """
    nvme_list = []
    print("{0}{1} is checking NVMe drive".format(INFO, LOCAL_HOSTNAME))

    try:
        nvme_list = os.listdir('/sys/class/nvme/')
    except BaseException as e:
        print("{0}{1} tried to list /sys/class/nvme/ but hit ".format(WARNING,
              LOCAL_HOSTNAME) + "exception: {}".format(e))
        return True, []

    nvme_drive_num = 0
    if nvme_list:
        nvme_drive_num = len(nvme_list)

    fatal_error = False
    if nvme_drive_num <= 0:
        print("{0}{1} does not have any NVMe drive".format(WARNING,
              LOCAL_HOSTNAME))
        fatal_error = True
    elif nvme_drive_num == 1:
        print("{0}{1} has a total of {2} NVMe drive".format(INFO,
              LOCAL_HOSTNAME, nvme_drive_num))
    else:
        print("{0}{1} has a total of {2} NVMe drives".format(INFO,
              LOCAL_HOSTNAME, nvme_drive_num))

    return fatal_error, nvme_drive_num


def check_NVME_packages(packages_ch):
    fatal_error = False
    nvme_packages = {"nvme-cli": 0}
    if packages_ch:
        print("{0}{1} is checking package required by NVMe ".format(INFO,
              LOCAL_HOSTNAME) + "drive")
        nvme_packages_errors = package_check(nvme_packages)
        if nvme_packages_errors > 0:
            fatal_error = True
    return fatal_error


def check_SAS_packages(packages_ch):
    fatal_error = False
    sas_packages = {SAS_TOOL_ALIAS: 0}
    if packages_ch:
        print("{0}{1} is checking package required by SAS".format(INFO,
              LOCAL_HOSTNAME))
        sas_packages_errors = package_check(sas_packages)
        if sas_packages_errors > 0:
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
                " all NVMe drives have the same size")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe drives have the same size")
    except BaseException:
        fatal_error = True
        print(
            WARNING +
            LOCAL_HOSTNAME +
            " cannot query NVMe drives"
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

    if fatal_error is False:
        if duplicates > 0:
            fatal_error = True
            print(
                ERROR +
                LOCAL_HOSTNAME +
                " not all NVMe drives have unique IDs")
        else:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe drives have unique IDs")
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
    if fatal_error is False:
        if len(lba_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe drives have the same LBA size")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe drives have the same LBA size")
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
    if fatal_error is False:
        if len(md_unique_size) == 1:
            print(
                INFO +
                LOCAL_HOSTNAME +
                " all NVMe drives have the same metadata size")
            if md_size == "0":
                print(
                    INFO +
                    LOCAL_HOSTNAME +
                    " all NVMe drives have 0 metadata size")
            else:
                fatal_error = True
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " not all NVMe drives have 0 metadata size")
        else:
            print(
                WARNING +
                LOCAL_HOSTNAME +
                " not all NVMe drives have the same metadata size")
    return fatal_error


def check_tuned_profile():
    """
    Params:
    Returns:
        0 if tuned profile is OK.
        1 if tuned profile is not OK.
        exit directly if hit exception.
    """
    # is tuned active
    cmd = 'systemctl is-active tuned'
    out, err, rc = run_shell_cmd(cmd)
    out = out.strip()
    err = err.strip()
    if rc != 0:
        print("{0}{1} tuned is not active".format(ERROR, LOCAL_HOSTNAME))
        if err:
            print("{0}{1} checked tuned active status hit error: {2}".format(
                  ERROR, LOCAL_HOSTNAME, err))
        if 'inactive' in out:
            print("{0}{1} Please start tuned if it is inactive".format(ERROR,
                  LOCAL_HOSTNAME))
        return 1

    # restart tuned to apply current profile
    cmd = 'systemctl restart tuned'
    _, err, rc = run_shell_cmd(cmd)
    err = err.strip()
    if rc != 0:
        print("{0}{1} cannot restart tuned".format(ERROR, LOCAL_HOSTNAME))
        if err:
            print("{0}{1} tried to restart tuned but hit error: ".format(
                  ERROR, LOCAL_HOSTNAME) + "{}".format(err))
        return 1

    # run tune-adm
    cmd = 'tuned-adm active'
    out, err, rc = run_shell_cmd(cmd)
    out = out.strip()
    err = err.strip()
    if rc != 0:
        print("{0}{1} failed to show current active profile".format(ERROR,
              LOCAL_HOSTNAME))
        if err:
            print("{0}{1} tried to show current active profile ".format(
                  ERROR, LOCAL_HOSTNAME) + "but hit error: {}".format(err))
        return 1
    if not out:
        print("{0}{1} showed current active profile but got ".format(ERROR,
              LOCAL_HOSTNAME) + "nothing")
        return 1

    matched = False
    for tuned in COMPATIBLE_TUNEDS:
        tuned_str = "Current active profile: {}".format(tuned)
        if tuned_str in out:
            matched = True
            print("{0}{1} has current tuned profile: {2}".format(INFO,
                  LOCAL_HOSTNAME, tuned))
            cmd = 'tuned-adm verify'
            _, err, rc = run_shell_cmd(cmd)
            if rc != 0:
                print("{0}{1} cannot verify tuned profile".format(ERROR,
                      LOCAL_HOSTNAME))
                if err:
                    print("{0}{1} tried to verify tuned ".format(ERROR,
                          LOCAL_HOSTNAME) + "profile but hit error: " +
                          "{}".format(err))
                return 1
            print("{0}{1} current tuned profile matched ".format(INFO,
                  LOCAL_HOSTNAME) + "system settings")

    if matched is False:
        try:
            curr_profile = out.split()[-1]
        except BaseException as e:
            print("{0}{1} tried to extract current tuned ".format(ERROR,
                  LOCAL_HOSTNAME) + "profile but hit exception: " +
                  "{}".format(e))
            return 1
        print("{0}{1} has incorrect tuned profile: {2}. ".format(ERROR,
              LOCAL_HOSTNAME, curr_profile) + "Please refer to " +
              "{} ".format(TUNED_TOOL) + "to reset it")
        return 1
    return 0


def check_scsi_controller(scsi_ctrl_kv):
    """
    Params:
        scsi_ctrl_kv: Key-value of SCSI controller that already supported.
    Returns:
        (fatal_error, check_disks, scsi_controllers)
        fatal_error: True if hit error, else, False.
        check_disks: True if disks need to be check, else, False.
                     Is this necessary?
        scsi_controllers: SCSI controller list of localhost.
        exit directly if hit error
    """
    if not scsi_ctrl_kv or isinstance(scsi_ctrl_kv, dict) is False:
        print("{0}{1} Invalid parameter: scsi_ctrl_kv".format(ERROR,
              LOCAL_HOSTNAME))
        return False, False, []
    print("{0}{1} is checking SCSI controller".format(INFO, LOCAL_HOSTNAME))
    cmd = 'lspci'
    out, err, rc = run_shell_cmd(cmd)
    out = out.strip()
    err = err.strip()
    if rc != 0 or not out:
        print("{0}{1} ran cmd: '{2}'".format(ERROR, LOCAL_HOSTNAME, cmd))
        if err:
            print("{0}{1} hit error:\n{2}".format(WARNING, LOCAL_HOSTNAME,
                  err))
        if not out:
            print("{0}{1} got nothing".format(WARNING, LOCAL_HOSTNAME))
        return False, False, []
    out_lines = out.splitlines()
    # Get alternative SAS adapters
    alt_controllers = []
    for line in out_lines:
        if 'SCSI storage controller' not in line and \
            'SCSI controller' not in line and \
            'SAS' not in line and \
            'MegaRAID' not in line:
            continue
        try:
            scsi_ctrl = line.split(':')[-1].strip()
        except BaseException as e:
            sys.exit("{0}{1} tried to extract SCSI controller ".format(ERROR,
                     LOCAL_HOSTNAME) + "from '{}' but hit ".format(line) +
                     "exception: {}\n".format(e))
        alt_controllers.append(scsi_ctrl)
    logging.debug("Got alt_controllers={}".format(alt_controllers))
    if not alt_controllers:
        print("{0}{1} does not have any SCSI controller".format(INFO,
              LOCAL_HOSTNAME))
        return False, False, []

    # supported SCSI controller
    supp_ctrlrs = []
    try:
        raw_ctrls = list(scsi_ctrl_kv.keys())
        supp_ctrlrs = [i for i in raw_ctrls if i != 'json_version']
    except BaseException as e:
        sys.exit("{0}{1} tried to extract supported SCSI ".format(ERROR,
                 LOCAL_HOSTNAME) + "controller but hit exception: " +
                 "{}\n".format(e))
    if not supp_ctrlrs:
        sys.exit("{0}{1} got empty supported SCSI controller\n".format(
                 ERROR, LOCAL_HOSTNAME))
    supp_len = len(supp_ctrlrs)

    scsi_controllers = []
    ok_controllers = []
    not_ok_controllers = []
    reserved_controllers = []
    not_tested_controllers = []
    for ctrlr in alt_controllers:
        ctrlr_list = ctrlr.split()
        if not ctrlr_list:
            continue
        not_match_cnt = 0
        for key in supp_ctrlrs:
            try:
                val = scsi_ctrl_kv[key]
            except KeyError as e:
                sys.exit()
            key_list = key.split()
            if not key_list:
                continue
            matched = set(key_list).issubset(set(ctrlr_list))
            if matched is True:
                if val == 'OK':
                    scsi_controllers.append(ctrlr)
                    ok_controllers.append(ctrlr)
                elif val == 'NOK':
                    scsi_controllers.append("{} [NOT OK]".format(ctrlr))
                    not_ok_controllers.append(ctrlr)
                else:
                    scsi_controllers.append("{0} [{1}]".format(ctrlr, val))
                    reserved_controllers.append("{0} [{1}]".format(ctrlr, val))
            else:
                not_match_cnt += 1
        if not_match_cnt == supp_len:
            scsi_controllers.append("{} [NOT TESTED]".format(ctrlr))
            not_tested_controllers.append(ctrlr)
    if not scsi_controllers:
        print("{0}{1} failed to generate SCSI controller list".format(ERROR,
              LOCAL_HOSTNAME))
        return False, False, []
    lspci_ctrlr_num = len(scsi_controllers)

    # storcli management
    storcli_ctrlr_num = get_controller_number_by_storcli()
    speed_ok = 'none'
    # Below variable means checking disks by storcli
    check_disks = False
    need_to_run_stortool = False
    ctrlr_speeds = []
    if storcli_ctrlr_num == 0:
        print("{0}{1} has no SCSI controller managed by {2}".format(WARNING,
              LOCAL_HOSTNAME, SAS_TOOL_ALIAS))
    elif storcli_ctrlr_num > 0:
        check_disks = True
        if storcli_ctrlr_num == 1:
            print("{0}{1} has 1 SCSI controller managed by {2}".format(INFO,
                  LOCAL_HOSTNAME, SAS_TOOL_ALIAS))
        else:
            print("{0}{1} has {2} SCSI controllers managed by {3}".format(INFO,
                  LOCAL_HOSTNAME, storcli_ctrlr_num, SAS_TOOL_ALIAS))

        if lspci_ctrlr_num != storcli_ctrlr_num:
            print("{0}{1} lspci got {2} SCSI controller[s] but ".format(WARNING,
                  LOCAL_HOSTNAME, lspci_ctrlr_num) + "{0} got {1} ".format(
                  SAS_TOOL_ALIAS, storcli_ctrlr_num) + "SCSI controller[s]")

        ctrlr_speeds = get_scsi_controller_speed()
        if not ctrlr_speeds:
            need_to_run_stortool = True
            print("{0}{1} failed to get any SCSI controller ".format(WARNING,
                  LOCAL_HOSTNAME) + "speed")
        else:
            speed_len = len(ctrlr_speeds)
            if speed_len < storcli_ctrlr_num:
                need_to_run_stortool = True
                print("{0}{1} got {2} kind[s] of SCSI controller ".format(WARNING,
                      LOCAL_HOSTNAME, speed_len) + "speed which is less than " +
                      "{} SCSI controller number".format(storcli_ctrlr_num))
            elif speed_len > storcli_ctrlr_num:
                need_to_run_stortool = True
                print("{0}{1} got {2} kind[s] of SCSI controller ".format(WARNING,
                      LOCAL_HOSTNAME, speed_len) + "speed which is more than " +
                      "{} SCSI controller number".format(storcli_ctrlr_num))
            else:
                speed_ok = 'none'
                if all(ACC_CTRLR_SPEED in i for i in ctrlr_speeds) is True:
                    # All controller speed contains ACC_CTRLR_SPEED
                    speed_ok = 'all'
                else:
                    if any(ACC_CTRLR_SPEED in i for i in ctrlr_speeds) is True:
                        # Partial controller speed contains ACC_CTRLR_SPEED
                        speed_ok = 'partial'
                        need_to_run_stortool = True
                    else:
                        speed_ok = 'none'
                        need_to_run_stortool = True
                if storcli_ctrlr_num == 1:
                    if speed_ok == 'all':
                        print("{0}{1} has a {2} SCSI controller".format(INFO,
                              LOCAL_HOSTNAME, ACC_CTRLR_SPEED))
                    elif speed_ok == 'none':
                        print("{0}{1} has a SCSI controller but ".format(WARNING,
                              LOCAL_HOSTNAME) + "its speed is NOT {}".format(
                              ACC_CTRLR_SPEED))
                else:
                    if speed_ok == 'all':
                        print("{0}{1} has {2} {3} SCSI controllers".format(INFO,
                              LOCAL_HOSTNAME, storcli_ctrlr_num, ACC_CTRLR_SPEED))
                    elif speed_ok == 'partial':
                        print("{0}{1} has {2} SCSI controllers ".format(WARNING,
                              LOCAL_HOSTNAME, storcli_ctrlr_num) + "but NOT " +
                              "all of them have acceptable {} speed".format(
                              ACC_CTRLR_SPEED))
                    elif speed_ok == 'none':
                        print("{0}{1} has {2} SCSI controllers but ".format(WARNING,
                              LOCAL_HOSTNAME, storcli_ctrlr_num) + "none of " +
                              "them has acceptable {} speed".format(ACC_CTRLR_SPEED))

    fatal_error = False
    if ok_controllers:
        logging.debug("Got ok_controllers={}".format(ok_controllers))
        ok_ctrlr_len = len(ok_controllers)
        if ok_ctrlr_len == 1:
            print("{0}{1} has following SCSI controller tested by ".format(INFO,
                  LOCAL_HOSTNAME) + "IBM")
        else:
            print("{0}{1} has following SCSI controllers tested by ".format(INFO,
                  LOCAL_HOSTNAME) + "IBM")
        for ctrlr in ok_controllers:
            print("{0}{1} {2}".format(INFO, LOCAL_HOSTNAME, ctrlr))
        if ok_ctrlr_len == 1:
            print("{0}{1} disks attached to above SCSI controller ".format(INFO,
                  LOCAL_HOSTNAME) + "can be used by ECE")
        else:
            print("{0}{1} disks attached to above {2} SCSI ".format(INFO,
                  LOCAL_HOSTNAME, ok_ctrlr_len) + "controllers can be " +
                  "used by ECE")
    if not_ok_controllers:
        logging.debug("Got not_ok_controllers={}".format(not_ok_controllers))
        notok_ctrlr_len = len(not_ok_controllers)
        fatal_error = True
        if notok_ctrlr_len == 1:
            print("{0}{1} has following SCSI controller ".format(ERROR,
                  LOCAL_HOSTNAME) + "explicitly NOT supported by ECE")
        else:
            print("{0}{1} has following SCSI controllers ".format(ERROR,
                  LOCAL_HOSTNAME) + "explicitly NOT supported by ECE")
        for ctrlr in not_ok_controllers:
            print("{0}{1} {2}".format(ERROR, LOCAL_HOSTNAME, ctrlr))
        if notok_ctrlr_len == 1:
            print("{0}{1} disks attached to above SCSI ".format(ERROR,
                  LOCAL_HOSTNAME) + "controller can NOT be used by ECE")
        else:
            print("{0}{1} disks attached to above {2} SCSI ".format(ERROR,
                  LOCAL_HOSTNAME, notok_ctrlr_len) + "controllers can " +
                  "NOT be used by ECE")
    if reserved_controllers:
        logging.debug("Got reserved_controllers={}".format(reserved_controllers))
        need_to_run_stortool = True
        rsvd_ctrlr_len = len(reserved_controllers)
        if rsvd_ctrlr_len == 1:
            print("{0}{1} has following SCSI controller ".format(WARNING,
                  LOCAL_HOSTNAME) + "tagged by IBM")
        else:
            print("{0}{1} has following SCSI controllers ".format(WARNING,
                  LOCAL_HOSTNAME) + "tagged by IBM")
        for ctrlr in reserved_controllers:
            print("{0}{1} {2}".format(WARNING, LOCAL_HOSTNAME, ctrlr))
        if rsvd_ctrlr_len == 1:
            print("{0}{1} disks attached to above SCSI ".format(WARNING,
                  LOCAL_HOSTNAME) + "controller may be used by ECE, " +
                  "depends on the tag")
        else:
            print("{0}{1} disks attached to above {2} SCSI ".format(WARNING,
                  LOCAL_HOSTNAME, rsvd_ctrlr_len) + "controllers may be " +
                  "used by ECE, depends on the tag")
    if not_tested_controllers:
        logging.debug("Got not_tested_controllers={}".format(
                      not_tested_controllers))
        need_to_run_stortool = True
        not_tstd_ctrlr_len = len(not_tested_controllers)
        if not_tstd_ctrlr_len == 1:
            print("{0}{1} has following SCSI controller ".format(WARNING,
                  LOCAL_HOSTNAME) + "NOT tested by IBM")
        else:
            print("{0}{1} has following SCSI controllers ".format(WARNING,
                  LOCAL_HOSTNAME) + "NOT tested by IBM")
        for ctrlr in not_tested_controllers:
            print("{0}{1} {2}".format(WARNING, LOCAL_HOSTNAME, ctrlr))
        if not_tstd_ctrlr_len == 1:
            print("{0}{1} disks attached to above SCSI ".format(WARNING,
                  LOCAL_HOSTNAME) + "controller may NOT be used by ECE")
        else:
            print("{0}{1} disks attached to above {2} SCSI ".format(WARNING,
                  LOCAL_HOSTNAME, not_tstd_ctrlr_len) + "controllers " +
                  "may NOT be used by ECE")

    if need_to_run_stortool is True and check_disks is True:
        print("{0}{1} needs to run {2}".format(INFO, LOCAL_HOSTNAME,
              STORAGE_TOOL))
    return fatal_error, check_disks, scsi_controllers


def check_vmware_scsi_controller(supported_sas_ctrl_dict):
    """
    Params:
        supported_sas_ctrl_dict - SAS controller supported in SAS_adapters.json
    Returns:
        Directly exits if hit fatal error
        scsi_ctrl_dict - {'PCI address': 'SCSI controller', ...}
            Populated SCSI controller which is in supported_sas_ctrl_dict
    """
    if supported_sas_ctrl_dict and isinstance(supported_sas_ctrl_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter supported_sas_ctrl_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, supported_sas_ctrl_dict))

    print("{0}{1} checking SCSI controller".format(INFO, LOCAL_HOSTNAME))
    # Initialize scsi_ctrl_dict
    scsi_ctrl_dict = {}
    cmd = 'lspci'
    cmd_out, err, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    err = err.strip()
    if err:
        print("{0}{1} queried SCSI conftroller by running cmd: {2}. ".
            format(WARNING, LOCAL_HOSTNAME, cmd) +
            "Hit error: {}".format(err))
        return scsi_ctrl_dict
    if not cmd_out:
        print("{0}{1} got nothing by running cmd: {2}".format(INFO,
            LOCAL_HOSTNAME, cmd))
        print("{0}{1} does not have any SCSI conftroller at all".
            format(INFO, LOCAL_HOSTNAME))
        return scsi_ctrl_dict

    lspci_out_list = cmd_out.splitlines()
    # Get alternative SCSI controllers
    alt_scsi_ctrl_list = []
    for line in lspci_out_list:
        #if 'SATA controller' not in line and \
        if 'SCSI storage controller' not in line and \
           'SCSI controller' not in line and \
           'SAS' not in line and \
           'MegaRAID' not in line:
            continue
        try:
            pci_addr = line.split(' ', 1)[0]
            scsi_ctrl = line.split(':')[-1]
            alt_scsi_ctrl_list.append("{0} {1}".format(pci_addr, scsi_ctrl))
        except BaseException as e:
            sys.exit("{0}{1} tried to extract SCSI controller from {2}. ".
                format(ERROR, LOCAL_HOSTNAME, line) + "Hit exception: {}".
                format(e))
    logging.debug("Got alt_scsi_ctrl_list=%s", alt_scsi_ctrl_list)

    if not alt_scsi_ctrl_list:
        print("{0}{1} cannot get any SCSI controller from output of cmd: {2}".
            format(INFO, LOCAL_HOSTNAME, cmd))
        return scsi_ctrl_dict

    marked_ok_scsi_ctrl_list = []
    marked_ok_name_list = []
    for alt_scsi_ctrl in alt_scsi_ctrl_list:
        for key in supported_sas_ctrl_dict.keys():
            if key == 'json_version':
                continue
            try:
                scsi_ctrl_name = alt_scsi_ctrl.split(' ', 1)[-1]
            except BaseException as e:
                sys.exit("{0}{1} tried to extract SCSI controller name from ".
                    format(ERROR, LOCAL_HOSTNAME) + "{0}. Hit exception: {1}".
                    format(alt_scsi_ctrl, e))
            if key in scsi_ctrl_name:
                if supported_sas_ctrl_dict[key] == 'OK':
                    # Marked 'OK'
                    marked_ok_scsi_ctrl_list.append(alt_scsi_ctrl)
                    marked_ok_name_list.append(scsi_ctrl_name.strip())

    logging.debug("Got marked_ok_scsi_ctrl_list=%s", marked_ok_scsi_ctrl_list)

    alt_scsi_ctrl_count = len(alt_scsi_ctrl_list)
    ok_count = len(marked_ok_scsi_ctrl_list)
    if ok_count > alt_scsi_ctrl_count:
        sys.exit("{0}{1} got invalid supported SCSI controller list: {2}. Over flow".
            format(ERROR, LOCAL_HOSTNAME, marked_ok_scsi_ctrl_list))
    elif ok_count <= 0:
        print("{0}{1} cannot find any supported SCSI controller to run ECE".
            format(INFO, LOCAL_HOSTNAME))
        return scsi_ctrl_dict
    else:
        # 0 < ok_count <= alt_scsi_ctrl_count
        print("{0}{1} has {2} tested by IBM".
            format(INFO, LOCAL_HOSTNAME, ", ".join(marked_ok_name_list)))
        print("{0}{1} disk attached to above SCSI controller could be ".
            format(INFO, LOCAL_HOSTNAME) + "used by ECE")
        for ok_scsi_ctrl in marked_ok_scsi_ctrl_list:
            try:
                scsi_ctrl_addr = ok_scsi_ctrl.split(' ', 1)[0].strip()
                scsi_ctrl_name = ok_scsi_ctrl.split(' ', 1)[-1].strip()
            except BaseException as e:
                sys.exit("{0}{1} tried to extract SCSI controller info from {2}. ".
                    format(ERROR, LOCAL_HOSTNAME, ok_scsi_ctrl) +
                    "Hit exception: {}".format(e))
            scsi_ctrl_dict[scsi_ctrl_addr] = scsi_ctrl_name
        logging.debug("Got scsi_ctrl_dict=%s", scsi_ctrl_dict)

        if ok_count == alt_scsi_ctrl_count:
            # All SCSI controller are in support list
            print("{0}{1} Please run storage acceptance tool at {2}".
                format(INFO, LOCAL_HOSTNAME, STORAGE_TOOL))
            return scsi_ctrl_dict

        # ok_count < alt_scsi_ctrl_count
        not_ok_count = alt_scsi_ctrl_count - ok_count
        not_ok_scsi_ctrl_list = \
            [i for i in alt_scsi_ctrl_list if i not in marked_ok_scsi_ctrl_list]
        logging.debug("Got not_ok_scsi_ctrl_list=%s", not_ok_scsi_ctrl_list)
        generated_not_ok_count = len(not_ok_scsi_ctrl_list)
        if generated_not_ok_count != not_ok_count:
            sys.exit("{0}{1} generated invalid unsupported SCSI controller list: {2}".
                format(ERROR, LOCAL_HOSTNAME, not_ok_scsi_ctrl_list))

        notok_name_list = []
        for notok_scsi_ctrl in not_ok_scsi_ctrl_list:
            # Re-set scsi_ctrl_name to ''
            scsi_ctrl_name = ''
            try:
                scsi_ctrl_addr = notok_scsi_ctrl.split(' ', 1)[0].strip()
                scsi_ctrl_name = notok_scsi_ctrl.split(' ', 1)[-1].strip()
            except BaseException as e:
                sys.exit("{0}{1} tried to extract NOT-OK SCSI controller address from ".
                    format(ERROR, LOCAL_HOSTNAME) + "{0}. Hit exception: {1}".
                    format(notok_scsi_ctrl, e))
            scsi_ctrl_dict[scsi_ctrl_addr] = "{} [NOT TESTED]".format(scsi_ctrl_name)
            notok_name_list.append(scsi_ctrl_name.strip())

        print("{0}{1} has {2} NOT tested by IBM".
            format(WARNING, LOCAL_HOSTNAME, ", ".join(notok_name_list)))
        print("{0}{1} disk attached to above SCSI controller cannot be used by ECE".
            format(WARNING, LOCAL_HOSTNAME))

        return scsi_ctrl_dict


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


def get_controller_number_by_storcli():
    """
    Params:
    Returns:
        controller_number: SCSI controller number detected by storcli.
    Remarks:
        ECE can be installed in server with disk directly attached to PCIe.
    """
    cmd = "{} show".format(SAS_TOOL)
    out, err, rc = run_shell_cmd(cmd)
    if rc != 0:
        print("{0}{1} failed to run cmd: '{2}'".format(WARNING, LOCAL_HOSTNAME,
              cmd))
        if err:
            print("{0}{1} hit error: {2}".format(WARNING, LOCAL_HOSTNAME, err))
        return 0
    if not out:
        print("{0}{1} ran cmd: '{2}' but got ".format(WARNING, LOCAL_HOSTNAME,
              cmd) + "nothing")
        return 0
    out_lines = out.splitlines()
    controller_number = 0
    for line in out_lines:
        if 'Number of Controllers =' not in line:
            continue
        line_to_list = line.split('=')
        try:
            number = line_to_list[-1].strip()
            controller_number = int(number)
        except BaseException as e:
            print("{0}{1} tried to extract controller ".format(WARNING,
                  LOCAL_HOSTNAME) + "number but hit exception: " +
                  "{}".format(e))
    logging.debug("Got SCSI controller number={}".format(controller_number))
    return controller_number


def get_scsi_controller_speed():
    """
    Params:
    Returns:
        (fatal_error, speeds)
        fatal_error: True, if hit exception. Else, False.
        speeds: a list to describe fabric SCSI controller speed.
    Remarks:
        ECE can be installed in server with disk directly attached to PCIe.
    """
    cmd = "{} /call show all".format(SAS_TOOL)
    out, err, rc = run_shell_cmd(cmd)
    if rc != 0:
        print("{0}{1} failed to run cmd: '{2}'".format(WARNING, LOCAL_HOSTNAME,
              cmd))
        if err:
            print("{0}{1} hit error: {2}".format(WARNING, LOCAL_HOSTNAME, err))
        return []
    if not out:
        print("{0}{1} ran cmd: '{2}' but got ".format(WARNING, LOCAL_HOSTNAME,
              cmd) + "nothing")
        return []
    out_lines = out.splitlines()
    speeds = []
    for line in out_lines:
        if 'Device Interface =' not in line:
            continue
        line_to_list = line.split('=')
        try:
            speed = line_to_list[-1].strip()
        except BaseException as e:
            print("{0}{1} tried to extract controller ".format(WARNING,
                  LOCAL_HOSTNAME) + "speed but hit exception: " +
                  "{}".format(e))
        if speed:
            speeds.append(speed)
    logging.debug("Got SCSI controller speeds={}".format(speeds))
    return speeds


def dpofua_check(sata_drive):
    """
    Params:
        sata_drive: SATA device.
    Returns:
        True if checking passed.
        False if checking did not pass.
    """
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
            print("{0}{1} cannot get DpoFua value from ".format(WARNING,
                  LOCAL_HOSTNAME) + "SATA device {}".format(sata_drive))
            dpofua_check_passed = False
        else:
            dpofua_value = dpofua[-1]
            if dpofua_value == "1":
                print("{0}{1} has SATA device {2} whose ".format(INFO,
                      LOCAL_HOSTNAME, sata_drive) + "DpoFua is " +
                      "{}".format(dpofua_value))
                dpofua_check_passed = True
            else:
                print("{0}{1} has SATA device {2} whose ".format(WARNING,
                      LOCAL_HOSTNAME, sata_drive) + "DpoFua is " +
                      "{}. It should be set to 1".format(dpofua_value))
                dpofua_check_passed = False
    except BaseException as e:
        print("{0}{1} tried to get DpoFua value of SATA ".format(WARNING,
              LOCAL_HOSTNAME) + "device {} but ".format(sata_drive) +
              "hit exception: {}".format(e))
        dpofua_check_passed = False
    return dpofua_check_passed


def sct_erc_check(sata_drive):
    """
    Params:
        sata_drive: SATA device.
    Returns:
        True if checking passed
        False if checking did not pass
    """
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
                scterc_read_sec = sct_erc_read / 10.0
                scterc_write_sec = sct_erc_write / 10.0
                if max(sct_erc_read, sct_erc_write) <= 100:
                    # We have both more than 10 seconds
                    print("{0}{1} has SATA device {2} whose ".format(INFO,
                          LOCAL_HOSTNAME, sata_drive) + "SCT ERC Read " +
                          "is {0} sec, Write is {1} sec".format(
                          scterc_read_sec, scterc_write_sec))
                    sct_erc_check_passed = True
                    return sct_erc_check_passed
                else:
                    print("{0}{1} has SATA device {2} whose ".format(WARNING,
                          LOCAL_HOSTNAME, sata_drive) + "SCT ERC Read " +
                          "is {0} sec, Write is {1} sec. ".format(
                          scterc_read_sec, scterc_write_sec) + "They must " +
                          "be less than 10.0 seconds")
                    sct_erc_check_passed = False
                    return sct_erc_check_passed
            else:
                # Something is not right, we fail
                print("{0}{1} cannot get correct SCT ERC ".format(WARNING,
                      LOCAL_HOSTNAME) + "Read or Write value of SATA " +
                      "device {}".format(sata_drive))
                sct_erc_check_passed = False
        else:
            print("{0}{1} has SATA device {2} does NOT ".format(WARNING,
                  LOCAL_HOSTNAME, sata_drive) + "support SCT Error " +
                  "Recovery Control")
        sct_erc_check_passed = False
    except BaseException as e:
        print("{0}{1} tried to get SCT ERC value of SATA ".format(ERROR,
              LOCAL_HOSTNAME) + "device {} but ".format(sata_drive) +
              "hit exception: {}".format(e))
        sct_erc_check_passed = False
    return sct_erc_check_passed


def sata_checks(SATA_drives):
    # We do perform some SATA checks
    errors = 0
    for sata_drive in SATA_drives:
        dpofua_pass = dpofua_check(sata_drive)
        if dpofua_pass is False:
            errors = errors + 1
        sct_erc_pass = sct_erc_check(sata_drive)
        if sct_erc_pass is False:
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
        if number_of_SATA_drives <= 0 and sata_on is True:
            print("{0}{1} {2} does not detect any SATA device".format(WARNING,
                  LOCAL_HOSTNAME, SAS_TOOL_ALIAS))
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
                    print("{0}{1} is checking SATA setting".format(INFO, LOCAL_HOSTNAME))
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
                    SATA_OS_drives_to_check = list(set(SATA_OS_drives).difference(
                                                   uniq_partition_drives))
                    # We have a JBOD on OS issue here
                    print("{0}{1} is checking SATA setting".format(INFO, LOCAL_HOSTNAME))
                    sata_checks_passed = sata_checks(SATA_OS_drives_to_check)
                if sata_checks_passed:
                    # While we still pass the SATA checks we mark a failure here
                    # Someone has run this with SATA option so we want to cover a PASS
                    # When/If SATA goes GA the following line should be deleted
                    num_errors += 1
                    if number_of_SATA_drives == 1:
                        print("{0}{1} has a total of {2} SATA device ".format(WARNING,
                              LOCAL_HOSTNAME, number_of_SATA_drives) + "passed the " +
                              "SATA setting checks")
                    else:
                        print("{0}{1} has a total of {2} SATA devices ".format(WARNING,
                              LOCAL_HOSTNAME, number_of_SATA_drives) + "passed the " +
                              "SATA setting checks")
                else:
                    # Warning message because SATA device can be ignored
                    num_errors += 1
                    if number_of_SATA_drives == 1:
                        print("{0}{1} has a total of {2} SATA device did ".format(WARNING,
                              LOCAL_HOSTNAME, number_of_SATA_drives) + "NOT passed " +
                              "the SATA setting checks. It can NOT be used by ECE")
                    else:
                        print("{0}{1} has a total of {2} SATA devices did ".format(WARNING,
                              LOCAL_HOSTNAME, number_of_SATA_drives) + "NOT passed " +
                              "the SATA setting checks. They can NOT be used by ECE")
            else:
                # Throw a warning about presence of SATA drives
                if number_of_SATA_drives == 1:
                    print("{0}{1} has a total of {2} SATA device but it ".format(WARNING,
                          LOCAL_HOSTNAME, number_of_SATA_drives) + "can NOT be used " +
                          "by ECE")
                else:
                    print("{0}{1} has a total of {2} SATA devices but ".format(WARNING,
                          LOCAL_HOSTNAME, number_of_SATA_drives) + "they can NOT be " +
                          "used by ECE")
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
                if number_of_drives == 1:
                    print("{0}{1} has a total of {2} {3} ".format(INFO, LOCAL_HOSTNAME,
                          number_of_drives, device_type) + "with the same size")
                else:
                    print("{0}{1} has a total of {2} {3}s ".format(INFO, LOCAL_HOSTNAME,
                          number_of_drives, device_type) + "with the same size")
            else:
                # We should fail here if different sizes, but lets make warning
                # num_errors = num_errors + 1
                print("{0}{1} has a total of {2} {3} ".format(WARNING, LOCAL_HOSTNAME,
                      number_of_drives, device_type) + "devices with different sizes")
        else:
            num_errors = num_errors + 1

    except BaseException as e:
        num_errors = num_errors + 1
        number_of_drives = 0
        print("{0}{1} tried to get SAS|SATA information but hit ".format(WARNING,
              LOCAL_HOSTNAME) + "exception: {}".format(e))

    if num_errors != 0:
        fatal_error = True

    return fatal_error, number_of_drives, SAS_drives_dict


def map_scsi_addr_to_logical_name():
    """
    Params:
    Returns:
        Directly exits if hit fatal error
        mapping_dict - {'SCSI address': 'logical name', ...}
    """
    cmd = "lshw -class storage -quiet"
    cmd_out, err, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    err = err.strip()
    if err:
        sys.exit("{0}{1} queried storage info by running cmd: {2}. ".
            format(ERROR, LOCAL_HOSTNAME, cmd) +
            "Hit error: {}".format(err))
    if not cmd_out:
        sys.exit("{0}{1} got nothing by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))

    lshw_out_lines = cmd_out.splitlines()
    mapping_dict = {}
    scsi_key = ''
    for line in lshw_out_lines:
        line = line.strip()
        # Refresh desc_str for each interation
        logical_name = ''
        if 'bus info' in line and 'pci@' in line:
            try:
                scsi_key = line.split('pci@')[-1].strip()
            except BaseException as e:
                print("{0}{1} tried to extract bus info from {2}. ".
                    format(WARNING, LOCAL_HOSTNAME, line) +
                    "Hit exception: {}".format(e))
        if not scsi_key:
            # Skip empty PCI address
            continue
        if 'logical name:' in line and 'nvme' not in line:
            try:
                logical_name = line.split('logical name:')[-1].strip()
            except BaseException as e:
                print("{0}{1} tried to extract logical name from {2}. ".
                    format(WARNING, LOCAL_HOSTNAME, line) +
                    "Hit exception: {}".format(e))

        if not logical_name:
            # Skip if failed to extract logical name
            continue
        mapping_dict[scsi_key] = logical_name

    if not mapping_dict:
        logging.debug("Generate empty pciAddr-logicalName dictionary")
        logging.debug("For more info, run cmd: %s", cmd)

    return mapping_dict


def map_hctl_to_disktype():
    """
    Params:
    Returns:
        Directly exits if hit fatal error
        mapping_dict - {'H:T:C:L': 'SCSI Disk', ...}
    """
    cmd = "lshw -class disk -quiet"
    cmd_out, err, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    err = err.strip()
    if err:
        sys.exit("{0}{1} queried disk info by running cmd: {2} ".
            format(ERROR, LOCAL_HOSTNAME, cmd) +
            "Hit error: {}".format(err))
    if not cmd_out:
        sys.exit("{0}{1} got nothing by running cmd: {2}".
            format(ERROR, LOCAL_HOSTNAME, cmd))

    lshw_out_lines = cmd_out.splitlines()
    reversed_lshw_lines = list(reversed(lshw_out_lines))
    mapping_dict = {}
    hctl_key = ''
    for line in reversed_lshw_lines:
        line = line.strip()
        # Refresh desc_str for each interation
        desc_str = ''
        if 'bus info' in line and 'scsi@' in line:
            try:
                hctl_key = line.split('scsi@')[-1].strip().replace('.', ':')
            except BaseException as e:
                print("{0}{1} tried to extract bus info from {2}. ".
                    format(WARNING, LOCAL_HOSTNAME, line) +
                    "Hit exception: {}".format(e))
        if not hctl_key:
            # Skip empty H:T:C:L
            continue
        if 'description:' in line and 'NVMe disk' not in line:
            try:
                desc_str = line.split('description:')[-1].strip()
            except BaseException as e:
                print("{0}{1} tried to extract description from {2}. ".
                    format(WARNING, LOCAL_HOSTNAME, line) +
                    "Hit exception: {}".format(e))

        if not desc_str:
            # Skip if failed to extract description
            continue
        mapping_dict[hctl_key] = desc_str

    if not mapping_dict:
        print("{0}{1} cannot get busInfo-description mapping of disk".
            format(INFO, LOCAL_HOSTNAME))
        logging.debug("Generates empty H:C:T:L-diskType dictionary")

    return mapping_dict


def check_disk_wce_by_sginfo(disk_dict):
    """
    Params:
        disk_dict - Part of disk dictionary defined by this script
    Returns:
        Directly exits if hit fatal error
        (error_count, disk_dict)
        error_count - error count of WCE checking
        disk_dict - update input dict and make it look like:
        {
            'hctl': [size_decimal, size_unit, log_sec, model, wwn,
                    'mapping_success', kname, WCE_by_sginfo,
                    'storcli_WCE_unknown'],
            ...
        }
    """
    if disk_dict and isinstance(disk_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter disk_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, disk_dict))

    error_count = 0
    # Set WCE gotten from storcli as storcli_WCE_unknown to simulate physical checking
    storcli_wce = 'storcli_WCE_unknown'
    for val in disk_dict.values():
        # Re-set sginfo_wce as sg_WCE_unknown for each iteration
        sginfo_wce = 'sg_WCE_unknown'
        try:
            kname = val[6]
        except IndexError as e:
            error_count += 1
            val.append(sginfo_wce)
            val.append(storcli_wce)
            print("{0}{1} tried to extract disk kernel name from {2}. ".
                format(ERROR, LOCAL_HOSTNAME, val) +
                "Hit IndexError: {}".format(e))
            continue
        if not kname:
            error_count += 1
            val.append(sginfo_wce)
            val.append(storcli_wce)
            print("{0}{1} got empty disk kernel name from {2}".
                format(ERROR, LOCAL_HOSTNAME, val))
            continue

        get_wce_cmd = "/usr/bin/sginfo -c {}".format(kname)
        wce_cmd_out, err, _ = run_shell_cmd(get_wce_cmd, True)
        wce_cmd_out = wce_cmd_out.strip()
        err = err.strip()
        if err:
            error_count += 1
            val.append(sginfo_wce)
            val.append(storcli_wce)
            print("{0}{1} queried WCE info by running cmd: {2}. ".
                format(ERROR, LOCAL_HOSTNAME, get_wce_cmd) +
                "Hit error: {}".format(err))
            continue
        if not wce_cmd_out:
            error_count += 1
            val.append(sginfo_wce)
            val.append(storcli_wce)
            print("{0}{1} got empty sg-WCE info by running cmd: {2}".
                format(ERROR, LOCAL_HOSTNAME, get_wce_cmd))
            continue

        # SG drive: SCSI generic drive
        if 'no corresponding sg device found' in wce_cmd_out:
            error_count += 1
            val.append(sginfo_wce)
            val.append(storcli_wce)
            print("{0}{1} has {2} which is not a SCSI generic device".
                format(ERROR, LOCAL_HOSTNAME, kname))
            continue

        wce_out_lines = wce_cmd_out.splitlines()
        for line in wce_out_lines:
            if 'Write Cache Enabled' in line:
                try:
                    enable_flag = int(line.split()[-1])
                except BaseException as e:
                    error_count += 1
                    print("{0}{1} tried to extract sg-WCE flag from {2}. ".
                        format(WARNING, LOCAL_HOSTNAME, line) +
                        "Hit exception: {}".format(e))
                    break
                if enable_flag == 1:
                    error_count += 1
                    sginfo_wce = 'sg_WCE_enabled'
                    print("{0}{1} has {2} which is Write Cache Enabled. It".
                        format(ERROR, LOCAL_HOSTNAME, kname) +
                        " cannot be used by ECE")
                    break
                elif enable_flag == 0:
                    sginfo_wce = 'sg_WCE_disabled'
                    break
                else:
                    error_count += 1
                    print("{0}{1} has {2} which Write Cache Enabled is {3}".
                        format(WARNING, LOCAL_HOSTNAME, kname, line) +
                        ". That is NOT a standard format")
                logging.debug("%s has WCE info: %s", kname, line)

        val.append(sginfo_wce)
        val.append(storcli_wce)

    return error_count, disk_dict


def get_os_disk(lsblk_outlines):
    """
    Params:
        lsblk_outlines - output of lsblk
    Returns:
        Directly exits if hit fatal error
        os_disk_list - A list of disk which OS is installed
    """
    if lsblk_outlines and isinstance(lsblk_outlines, list):
        pass
    else:
        sys.exit("{0}{1} invalid parameter lsblk_outlines({2})".
            format(ERROR, LOCAL_HOSTNAME, lsblk_outlines))

    kname_regex = re.compile(r'KNAME=\"(.*?)\"')
    mntpt_regex = re.compile(r'MOUNTPOINT=\"(.*?)\"')
    os_disk_list = []
    for line in lsblk_outlines:
        try:
            kname = "".join(kname_regex.findall(line))
        except BaseException as e:
            sys.exit("{0}{1} failed to extract kname from {2}. Hit exception {3}".
                format(ERROR, LOCAL_HOSTNAME, line, e))
        if kname:
            kname = kname.strip()
            kname = "".join([i for i in kname if not i.isdigit()])
        else:
            continue

        try:
            mountpoint = "".join(mntpt_regex.findall(line))
        except BaseException as e:
            sys.exit("{0}{1} tried to extract mount-point from {2} Hit exception {3}".
                format(ERROR, LOCAL_HOSTNAME, line, e))
        if mountpoint:
            mountpoint = mountpoint.strip()
            if 'boot' in mountpoint:
                # Got disk on which OS was installed
                os_disk_list.append(kname)

    if os_disk_list:
        dedup_os_disk_list = list(set(os_disk_list))
        logging.debug("OS is installed on %s", dedup_os_disk_list)
        return dedup_os_disk_list
    else:
        logging.debug("OS disk is not found")
        return []


def get_partitioned_disk(lsblk_outlines, os_disk_list):
    """                          
    Params:                      
        lsblk_outlines - output of lsblk
        os_disk_list - disk list which OS is installed
    Returns:                     
        Directly exits if hit fatal error
        part_disk_list - A list of disk which is partitioned
    """
    if lsblk_outlines and isinstance(lsblk_outlines, list):
        pass
    else:
        sys.exit("{0}{1} invalid parameter lsblk_outlines({2})".
            format(ERROR, LOCAL_HOSTNAME, lsblk_outlines))

    kname_regex = re.compile(r'KNAME=\"(.*?)\"')
    base_kname_list = []
    for line in lsblk_outlines:
        try:
            kname = "".join(kname_regex.findall(line))
        except BaseException as e:
            sys.exit("{0}{1} tried to extract kname from {2}. Hit exception: {3}".
                format(ERROR, LOCAL_HOSTNAME, line, e))
        if kname:
            kname = kname.strip()
            kname = "".join([i for i in kname if not i.isdigit()])
            if '/dev/nvme' not in kname and \
               '/dev/dm' not in kname and \
               '/dev/sr' not in kname and \
               '/dev/loop' not in kname:
                if os_disk_list and isinstance(os_disk_list, list):
                    if kname not in os_disk_list:
                        base_kname_list.append(kname)
                else:
                    base_kname_list.append(kname)

    # {'/dev/sda': '1'} if /dev/sda has no partition
    # {'/dev/sda': '3'} if /dev/sda has two partitions /dev/sda1, /dev/sda2
    part_disk_dict = {}
    if base_kname_list:
        for kname in base_kname_list:
            try:
                part_disk_dict[kname] = part_disk_dict.get(kname, 0) + 1
            except BaseException as e:
                sys.exit("{0}{1} tried to calculate partition number of {2}. ".
                    format(ERROR, LOCAL_HOSTNAME, kname) + "Hit exception: {}".
                    format(e))

    part_disk_list = []
    if part_disk_dict:
        for key, val in part_disk_dict.items():
            if val > 1:
                part_disk_list.append(key)
                part_num = val - 1
                print("{0}{1} has {2} with {3} partition[s] which cannot be used".
                    format(WARNING, LOCAL_HOSTNAME, key, part_num) + " by ECE")
                print("{0}{1} For more info, run cmd: lsblk -p |grep {2}".
                    format(WARNING, LOCAL_HOSTNAME, key))

    return part_disk_list


def get_supported_scsi_id(scsi_ctrl_dict):
    """
    Params:
        scsi_ctrl_dict - SCSI controller dictionary
    Returns:
        Directly exits if hit fatal error
        supported_scsi_id_list - ['scsi0', 'scsi1', ...] 
    """
    if scsi_ctrl_dict and isinstance(scsi_ctrl_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter scsi_ctrl_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, scsi_ctrl_dict))

    scsi_map_dict = map_scsi_addr_to_logical_name()
    logging.debug("Called map_scsi_addr_to_logical_name, got scsi_map_dict=%s",
        scsi_map_dict)
    if not scsi_map_dict:
        sys.exit("{0}{1} cannot map SCSI address and its logical name".
            format(ERROR, LOCAL_HOSTNAME))

    supported_scsi_id_list = []
    for key in scsi_ctrl_dict.keys():
        if 'json_version' in key:
            continue
        # Re-set colon_div_scsi_addr_len to 0 for each iteration
        colon_div_scsi_addr_len = 0
        try:
            colon_div_scsi_addr_len = len(key.split(':'))
        except BaseException as e:
            sys.exit("{0}{1} tried to extract length of colon divided ".
                format(ERROR, LOCAL_HOSTNAME) + "SCSI address. Hit " +
                "exception: {}".format(e))
        if colon_div_scsi_addr_len < 2 or colon_div_scsi_addr_len > 3:
            sys.exit("{0}{1} invalid length of colon divided SCSI ".
                format(ERROR, LOCAL_HOSTNAME) + "address {}".format(key))

        scsi_addr = key
        if colon_div_scsi_addr_len == 2:
            # Update SCSI address to standard format
            scsi_addr = "0000:{}".format(key)
        try:
            scsi_id = scsi_map_dict[scsi_addr]
        except KeyError:
            print("{0}{1} No disk attached to {2} with PCI address {3}".
                format(INFO, LOCAL_HOSTNAME, scsi_ctrl_dict[key], key))
            continue

        supported_scsi_id_list.append(scsi_id)

    if not supported_scsi_id_list:
        sys.exit("{0}{1} cannot generate supported SCSI ID list".
            format(ERROR, LOCAL_HOSTNAME))

    return supported_scsi_id_list


def check_disk_by_lsblk(scsi_ctrl_dict):
    """
    Params:
        scsi_ctrl_dict - {'PCI address': 'SCSI controller', ...}
    Returns:
        Directly exits if hit fatal error
        (hdd_error_count, hdd_wce_error_count, sas_hdd_disk_dict, 
         ssd_error_count, ssd_wce_error_count, sas_ssd_disk_dict,)
        hdd_error_count - error count of SAS HDD disk checking
        hdd_wce_error_count - error count of SAS HDD WCE checking
        sas_hdd_disk_dict - {
            'hctl':[size_decimal, size_unit, log_sec, model, wwn, 
            'mapping_success', kname, sg_wce, storcli_wce],
            ...
        }
        ssd_error_count - error count of SAS SSD disk checking
        ssd_wce_error_count - error count of SAS SSD WCE checking
        sas_ssd_disk_dict - {
            'hctl':[size_decimal, size_unit, log_sec, model, wwn,
            'mapping_success', kname, sg_wce, storcli_wce],
            ...
        }
    Remarks:
        Simulate physical checking
    """
    if scsi_ctrl_dict and isinstance(scsi_ctrl_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter scsi_ctrl_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, scsi_ctrl_dict))

    print("{0}{1} checking disk".format(INFO, LOCAL_HOSTNAME))

    hctl_map_dict = map_hctl_to_disktype()
    logging.debug("Called map_hctl_to_disktype, got hctl_map_dict=%s",
        hctl_map_dict)

    if not hctl_map_dict:
        print("{0}{1} does not have any disk attached to SCSI controller".
            format(INFO, LOCAL_HOSTNAME))
        return 0, 0, {}, 0, 0, {}

    supported_scsi_id_list = get_supported_scsi_id(scsi_ctrl_dict)
    logging.debug("Called get_supported_scsi_id, got " +
        "supported_scsi_id_list=%s", supported_scsi_id_list)

    # Some old Linux kernel versions did not support --json but --pairs
    out_opt = 'hctl,size,log-sec,model,wwn,kname,mountpoint,rota,state'
    cmd = "lsblk --path --output {} --pairs".format(out_opt)
    cmd_out, err, _ = run_shell_cmd(cmd)
    cmd_out = cmd_out.strip()
    err = err.strip()
    if err:
        print("{0}{1} queried block device info by running cmd: {2}. ".
            format(WARNING, LOCAL_HOSTNAME, cmd) +
            "Hit error: {}".format(err))
        return 1, 0, {}, 1, 0, {}
    if not cmd_out:
        print("{0}{1} cannot get block device info by running cmd: {2}".
            format(INFO, LOCAL_HOSTNAME, cmd))
        return 1, 0, {}, 1, 0, {}

    lsblk_lines = cmd_out.splitlines()
    os_disk_list = get_os_disk(lsblk_lines)
    logging.debug("Called get_os_disk, got lsblk_lines=%s", lsblk_lines)
    part_disk_list = get_partitioned_disk(lsblk_lines, os_disk_list)
    logging.debug("Called get_partitioned_disk, got part_disk_list=%s",
        part_disk_list)

    # Compile regular expressions
    hctl_regex  = re.compile(r'HCTL=\"(.*?)\"')
    size_regex  = re.compile(r'SIZE=\"(.*?)\"')
    lgsc_regex  = re.compile(r'LOG-SEC=\"(.*?)\"')
    model_regex = re.compile(r'MODEL=\"(.*?)\"')
    wwn_regex   = re.compile(r'WWN=\"(.*?)\"')
    kname_regex = re.compile(r'KNAME=\"(.*?)\"')
    mntpt_regex = re.compile(r'MOUNTPOINT=\"(.*?)\"')
    rota_regex  = re.compile(r'ROTA=\"(.*?)\"')
    state_regex = re.compile(r'STATE=\"(.*?)\"')

    sas_hdd_disk_dict = {}
    sas_ssd_disk_dict = {}
    sata_hdd_disk_dict = {}
    sata_ssd_disk_dict = {}
    improperly_attached_disk_dict = {}
    error_count = 0
    for line in lsblk_lines:
        try:
            hctl = "".join(hctl_regex.findall(line))
            size = "".join(size_regex.findall(line))
            log_sec = "".join(lgsc_regex.findall(line))
            model = "".join(model_regex.findall(line))
            wwn = "".join(wwn_regex.findall(line))
            kname = "".join(kname_regex.findall(line))
            mountpoint = "".join(mntpt_regex.findall(line))
            rota = "".join(rota_regex.findall(line))
            state = "".join(state_regex.findall(line))
        except BaseException as e:
            sys.exit("{0}{1} tried to extract item[s] from {2}. Hit exception: {3}".
                format(ERROR, LOCAL_HOSTNAME, line, e))

        hctl = hctl.strip()
        size = size.strip()
        log_sec = log_sec.strip()
        log_sec = "{}B".format(log_sec)
        model = model.strip()
        wwn = wwn.strip()
        kname = kname.strip()
        mountpoint = mountpoint.strip()
        rota = rota.strip()
        state = state.strip()

        if not hctl:
            # Skip if disk did not have H:T:C:L
            continue
        if not log_sec:
            # Skip if disk did not have logical sector size
            continue
        if not model:
            # Skip if disk did not have model
            continue
        if not wwn:
            # Skip if disk did not have wwn
            continue
        if not kname:
            # Skip if disk did not have kernel-name
            continue
        if not rota:
            # Skip if disk did not have rotation info
            continue

        # Create decimal size and its unit to be compatible with physical checking
        try:
            size_decimal = size[0:-1]
            size_raw_unit = size[-1]
        except BaseException as e:
            sys.exit("{0}{1} tried to generate decimal size and its unit from {2}.".
                format(ERROR, LOCAL_HOSTNAME, size) + " Hit exception: {}".
                format(e))
        try:
            size_float = float(size_decimal)
        except ValueError as e:
            sys.exit("{0}{1} tried to extract size of {2}. Hit ValueError: {3}".
                format(ERROR, LOCAL_HOSTNAME, kname, e))
        size_unit = ''
        if size_raw_unit.isalpha():
            size_unit = "{}iB".format(size_raw_unit)
        if not (size_float and size_unit):
            error_count += 1
            print("{0}{1} generated bad size info from {2}".format(ERROR,
                LOCAL_HOSTNAME, size))
            continue

        try:
            rota = int(rota)
        except ValueError as e:
            sys.exit("{0}{1} tried to extract integer rotation info from {2}. ".
                format(ERROR, LOCAL_HOSTNAME, rota) + "Hit ValueError: {}".
                format(e))

        if state not in ('running', 'live'):
            error_count += 1
            state_cmd = 'lsblk -p -o kname,state'
            print("{0}{1} has {2} which is not active. State is {3}".
                  format(ERROR, LOCAL_HOSTNAME, kname, state))
            logging.debug("Check state of %s by running cmd: %s",
                kname, state_cmd)
            continue

        # Check if disk was OS installed
        if kname in os_disk_list:
            continue

        # Check if disk was attached to incorrect SCSI controller
        try:
            curr_scsi_id = hctl.split(':', 1)[0]
        except BaseException as e:
            sys.exit("{0}{1} tried to extract SCSI ID from {2}. Hit exception: {3}".
                format(ERROR, LOCAL_HOSTNAME, hctl, e))
        curr_scsi_id = "scsi{}".format(curr_scsi_id)
        if curr_scsi_id not in supported_scsi_id_list:
            error_count += 1
            try:
                _ = improperly_attached_disk_dict[curr_scsi_id]
            except KeyError:
                improperly_attached_disk_dict[curr_scsi_id] = []
            improperly_attached_disk_dict[curr_scsi_id].append(kname)
            lshw_cmd = "lshw -c disk -quiet |grep '{}' -B1".format(kname)
            logging.debug("Check attached SCSI ID of %s by running cmd: %s",
                kname, lshw_cmd)
            continue

        # Check if disk was partitioned
        if kname in part_disk_list:
            error_count += 1
            continue

        # Check if disk was mounted
        if mountpoint:
            error_count += 1
            print("{0}{1} has {2} mounted to {3} which cannot be used by ECE".
                format(WARNING, LOCAL_HOSTNAME, kname, mountpoint))
            continue

        curr_disktype = ''
        try:
            curr_disktype = hctl_map_dict[hctl]
        except KeyError as e:
            error_count += 1
            print("{0}{1} tried to extract disk type of {2} with {3}. Hit ".
                format(ERROR, LOCAL_HOSTNAME, kname, hctl) + "KeyError: {}".
                format(e))

        if curr_disktype == 'SCSI Disk' and rota == 1:
            sas_hdd_disk_dict[hctl] = \
                [size_decimal, size_unit, log_sec, model, wwn, 'mapping_success', kname]
        elif curr_disktype == 'SCSI Disk' and rota == 0:
            sas_ssd_disk_dict[hctl] = \
                [size_decimal, size_unit, log_sec, model, wwn, 'mapping_success', kname]
        elif curr_disktype == 'ATA Disk' and rota == 1:
            sata_hdd_disk_dict[hctl] = \
                [size_decimal, size_unit, log_sec, model, wwn, 'mapping_success', kname]
        elif curr_disktype == 'ATA Disk' and rota == 0:
            sata_ssd_disk_dict[hctl] = \
                [size_decimal, size_unit, log_sec, model, wwn, 'mapping_success', kname]

    if improperly_attached_disk_dict:
        for key, val in improperly_attached_disk_dict.items():
            print("{0}{1} has {2} attached to unsupported SCSI controller with ".
                format(WARNING, LOCAL_HOSTNAME, ", ".join(val)) +
                "SCSI-ID: {}".format(key))

    hdd_error_count = error_count
    ssd_error_count = error_count
    if sata_hdd_disk_dict:
        hdd_error_count += 1
        sata_hdd_disk_list = []
        for val in sata_hdd_disk_dict.values():
            sata_hdd_disk_list.append(val[6])
        print("{0}{1} has SATA HDD {2} that cannot be used to run ECE".
            format(WARNING, LOCAL_HOSTNAME, ", ".join(sata_hdd_disk_list)))
        logging.debug("%s has sata_hdd_disk_dict=%s", LOCAL_HOSTNAME,
            sata_hdd_disk_dict)
    if sata_ssd_disk_dict:
        ssd_error_count += 1
        sata_ssd_disk_list = []
        for val in sata_ssd_disk_dict.values():
            sata_ssd_disk_list.append(val[6])
        print("{0}{1} has SATA SSD {2} that cannot be used to run ECE".
            format(WARNING, LOCAL_HOSTNAME, ", ".join(sata_ssd_disk_list)))
        logging.debug("%s has sata_ssd_disk_dict=%s", LOCAL_HOSTNAME,
            sata_ssd_disk_dict)

    hdd_wce_error_count = 0
    if not sas_hdd_disk_dict:
        hdd_error_count += 1
        print("{0}{1} has no proper SAS HDD to run ECE".format(INFO,
              LOCAL_HOSTNAME))
    else:
        if hdd_error_count > 0:
            sas_hdd_disk_list = []
            for val in sas_hdd_disk_dict.values():
                sas_hdd_disk_list.append(val[6])
            print("{0}{1} has SAS HDD {2} that can be used by ECE".
                format(INFO, LOCAL_HOSTNAME, ", ".join(sas_hdd_disk_list)))
        hdd_wce_error_count, sas_hdd_disk_dict = \
            check_disk_wce_by_sginfo(sas_hdd_disk_dict)
        logging.debug("Called check_disk_wce_by_sginfo, got hdd_wce_error_count=%s," +
            " sas_hdd_disk_dict=%s", hdd_wce_error_count, sas_hdd_disk_dict)

    ssd_wce_error_count = 0
    if not sas_ssd_disk_dict:
        ssd_error_count += 1
        print("{0}{1} has no proper SAS SSD to run ECE".format(INFO, LOCAL_HOSTNAME))
    else:
        if ssd_error_count > 0:
            sas_ssd_disk_list = []
            for val in sas_ssd_disk_dict.values():
                sas_ssd_disk_list.append(val[6])
            print("{0}{1} has SAS SSD {2} that can be used by ECE".
                format(INFO, LOCAL_HOSTNAME, sas_ssd_disk_list))
        ssd_wce_error_count, sas_ssd_disk_dict = \
            check_disk_wce_by_sginfo(sas_ssd_disk_dict)
        logging.debug("Called check_disk_wce_by_sginfo, got ssd_wce_error_count=%s," +
            " sas_ssd_disk_dict=%s", ssd_wce_error_count, sas_ssd_disk_dict)

    logging.debug("Got hdd_error_count=%s, ssd_error_count=%s", hdd_error_count,
        ssd_error_count)

    return hdd_error_count, hdd_wce_error_count, sas_hdd_disk_dict, \
           ssd_error_count, ssd_wce_error_count, sas_ssd_disk_dict


def check_SSD_loghome(SSD_dict, size):
    log_home_found = False
    print(SSD_dict)
    for SSD in SSD_dict:
        if convert_to_bytes(int(float(SSD_dict[SSD][0])),SSD_dict[SSD][1]) >= size:
            log_home_found = True
            break
    return log_home_found


def is_ssd_loghome_size_ok(ssd_dict, min_loghome_size):
    """
    Params:
        ssd_dict - Disk dictionary defined by this script
        min_loghome_size - MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json
    Returns:
        Directly exits if hit fatal error
        can_loghome_be_created - True if all SSDs met requirement, else, False
    """
    if ssd_dict and isinstance(ssd_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter ssd_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, ssd_dict))

    if min_loghome_size and isinstance(min_loghome_size, int):
        pass
    else:
        sys.exit("{0}{1} invalid parameter min_loghome_size({2})".
            format(ERROR, LOCAL_HOSTNAME, min_loghome_size))

    can_loghome_be_created = False
    for val in ssd_dict.values():
        int_capacity = 0
        capacity_unit = ''
        try:
            int_capacity = int(float(val[0]))
            capacity_unit = val[1]
        except BaseException as e:
            sys.exit("{0}{1} tried to extract capacity or its unit from".
                format(ERROR, LOCAL_HOSTNAME) +
                " {0}. Hit exception: {1}".format(val, e))

        cap_in_bytes = convert_to_bytes(int_capacity, capacity_unit)
        logging.debug("Called convert_to_bytes, got cap_in_bytes=%s",
            cap_in_bytes)
        if cap_in_bytes >= min_loghome_size:
            can_loghome_be_created = True
            break

    return can_loghome_be_created


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
                " cannot read WCE status for NVMe drives")

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


def check_vmware_storage(supported_sas_ctrl_dict,
                         min_loghome_size,
                         max_drives,
                         check_package,
                         sata_on=False):
    """
    Params:
        supported_sas_ctrl_dict: SAS controller supported in SAS_adapters.json.
        min_loghome_size: MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json.
        max_drives: MAX_DRIVES in HW_requirements.json.
        check_package: If True, check whether nvme-cli was installed or not.
        sata_on: False(default)|True(Not supported at present).
    Returns:
        (error_count, outputfile_segment_dict)
        exit if hit fatal error.
    Remarks:
        Simulate physical checking
    """
    if supported_sas_ctrl_dict and isinstance(supported_sas_ctrl_dict, dict):
        pass
    else:
        sys.exit("{0}{1} invalid parameter supported_sas_ctrl_dict({2})".
            format(ERROR, LOCAL_HOSTNAME, supported_sas_ctrl_dict))

    if min_loghome_size and isinstance(min_loghome_size, int):
        pass
    else:
        sys.exit("{0}{1} invalid parameter min_loghome_size({2})".
            format(ERROR, LOCAL_HOSTNAME, min_loghome_size))

    if max_drives and isinstance(max_drives, int):
        pass
    else:
        sys.exit("{0}{1} invalid parameter max_drives({2})".
            format(ERROR, LOCAL_HOSTNAME, max_drives))

    if isinstance(check_package, bool):
        pass
    else:
        sys.exit("{0}{1} invalid parameter check_package({2})".
            format(ERROR, LOCAL_HOSTNAME, check_package))

    if isinstance(sata_on, bool):
        pass
    else:
        sys.exit("{0}{1} invalid parameter sata_on({2})".
            format(ERROR, LOCAL_HOSTNAME, sata_on))

    if sata_on:
        sys.exit("{0}{1} does not support SATA disk checking in VMWare ".
            format(ERROR, LOCAL_HOSTNAME) + "environment at present")

    outputfile_segment_dict = {}
    scsi_ctrl_dict = check_vmware_scsi_controller(supported_sas_ctrl_dict)
    logging.debug("Called check_vmware_scsi_controller, got scsi_ctrl_dict=%s",
        scsi_ctrl_dict)

    error_count = 0
    HDD_n_of_drives = 0
    SSD_n_of_drives = 0
    n_NVME_drives = 0
    valid_drive_count = 0
    # SAS_fatal_error is from storcli checking.
    # Directly set it to Fasle for VMWare
    SAS_fatal_error = False
    # HDD_fatal_error is not important at present because ECE can be setup
    # on server with NVMe only or SSD only
    HDD_fatal_error = False
    SSD_fatal_error = False
    SAS_but_no_usable_drives = False
    SSD_log_home_found = False
    outputfile_segment_dict['error_SAS_card'] = SAS_fatal_error
    if SAS_fatal_error:
        # No SAS_fatal_error in VMWare
        outputfile_segment_dict['SAS_model'] = []
    else:
        SAS_model_list = []
        ok_scsi_ctrl_dict = {}
        for key, val in scsi_ctrl_dict.items():
            SAS_model_list.append(val)
            if 'NOT TESTED' not in val:
                ok_scsi_ctrl_dict[key] = val

        outputfile_segment_dict['SAS_model'] = SAS_model_list
        logging.debug("Got SAS_model=%s", SAS_model_list)
        logging.debug("Got ok_scsi_ctrl_dict=%s", ok_scsi_ctrl_dict)
        if ok_scsi_ctrl_dict:
            # It's unnecessary to check storcli package. Set False directly
            outputfile_segment_dict['SAS_packages_errors'] = False
            # Check if HDD is attached to correct SCSI controller
            HDD_fatal_error_count, HDD_WCE_error_count, HDD_dict, \
                SSD_fatal_error_count, SSD_WCE_error_count, SSD_dict = \
                check_disk_by_lsblk(ok_scsi_ctrl_dict)
            logging.debug("Called check_disk_by_lsblk, got HDD_fatal_error_count=%s" +
                ", HDD_WCE_error_count=%s, HDD_dict=%s, SSD_fatal_error_count=%s, " +
                "SSD_WCE_error_count=%s, SSD_dict=%s", HDD_fatal_error_count,
                HDD_WCE_error_count, HDD_dict, SSD_fatal_error_count,
                SSD_WCE_error_count, SSD_dict)

            HDD_fatal_error = bool(HDD_fatal_error_count)
            HDD_WCE_error = bool(HDD_WCE_error_count)
            if HDD_WCE_error:
                error_count += 1

            HDD_n_of_drives = len(HDD_dict)
            # Do not considered HDD_fatal_error at present
            if not HDD_WCE_error:
                valid_drive_count += HDD_n_of_drives
                print("{0}{1} has a total of {2} SAS HDD[s] that can be used by ECE".
                    format(INFO, LOCAL_HOSTNAME, HDD_n_of_drives))

            outputfile_segment_dict['HDD_fatal_error'] = HDD_fatal_error
            outputfile_segment_dict['HDD_n_of_drives'] = HDD_n_of_drives
            outputfile_segment_dict['HDD_drives'] = HDD_dict
            outputfile_segment_dict['HDD_WCE_error'] = HDD_WCE_error

            SSD_fatal_error = bool(SSD_fatal_error_count)
            SSD_WCE_error = bool(SSD_WCE_error_count)
            if SSD_WCE_error:
                error_count += 1

            SSD_n_of_drives = len(SSD_dict)
            if not (SSD_fatal_error or SSD_WCE_error):
                print("{0}{1} has a total of {2} SAS SSD[s] but more checks required".
                    format(INFO, LOCAL_HOSTNAME, SSD_n_of_drives))
                if SSD_dict:
                    SSD_log_home_found = \
                        is_ssd_loghome_size_ok(SSD_dict, min_loghome_size)
                    logging.debug("Called is_ssd_loghome_size_ok, got " +
                        "SSD_log_home_found=%s", SSD_log_home_found)

            outputfile_segment_dict['SSD_fatal_error'] = SSD_fatal_error
            outputfile_segment_dict['SSD_n_of_drives'] = SSD_n_of_drives
            outputfile_segment_dict['SSD_drives'] = SSD_dict
            outputfile_segment_dict['SSD_WCE_error'] = SSD_WCE_error

            if HDD_n_of_drives > 0 or SSD_n_of_drives > 0:
                SAS_but_no_usable_drives = False
            else:
                SAS_but_no_usable_drives = True
            outputfile_segment_dict['found_SAS_card_but_no_drives'] = \
                SAS_but_no_usable_drives
            logging.debug("Got found_SAS_card_but_no_drives=%s",
                SAS_but_no_usable_drives)

    NVME_error, n_NVME_drives = get_nvme_drive_num()
    logging.debug("Called get_nvme_drive_num, got NVME_error=%s, n_NVME_drives=%s",
        NVME_error, n_NVME_drives)

    outputfile_segment_dict['NVME_fatal_error'] = NVME_error
    outputfile_segment_dict['NVME_number_of_drives'] = n_NVME_drives
    NVME_dict = {}
    NVME_packages_errors = 0
    if not NVME_error:
        NVME_packages_errors = check_NVME_packages(check_package)
        outputfile_segment_dict['NVME_packages_errors'] = NVME_packages_errors
        logging.debug("Called check_NVME_packages, got NVME_packages_errors=%s",
            NVME_packages_errors)

    if NVME_packages_errors > 0:
        sys.exit("{0}{1} nvme-cli package is NOT installed".format(ERROR,
            LOCAL_HOSTNAME))
    else:
        NVME_error, NVME_dict = check_NVME_disks()
        logging.debug("Called check_NVME_disks, got NVME_error=%s, NVME_dict=%s",
            NVME_error, NVME_dict)

    loghome_error = False
    NVME_ID_dict = {}
    if n_NVME_drives > 0:
        NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
        outputfile_segment_dict['NVME_WCE_error'] = NVME_WCE_error
        logging.debug("Called check_WCE_NVME, got NVME_WCE_error=%s, " +
            "NVME_dict=%s", NVME_WCE_error, NVME_dict)
        if NVME_WCE_error:
            error_count += 1

        NVME_LBA_error = check_LBA_NVME(NVME_dict)
        outputfile_segment_dict['NVME_LBA_error'] = NVME_LBA_error
        logging.debug("Called check_LBA_NVME, got NVME_LBA_error=%s",
            NVME_LBA_error)
        if NVME_LBA_error:
            error_count += 1

        NVME_MD_error = check_MD_NVME(NVME_dict)
        outputfile_segment_dict['NVME_MD_error'] = NVME_MD_error
        logging.debug("Called check_MD_NVME, got NVME_MD_error=%s",
            NVME_LBA_error)
        if NVME_MD_error:
            error_count += 1

        NVME_DUPLICATE_ID_error, NVME_ID_dict = check_NVME_ID(NVME_dict)
        outputfile_segment_dict['NVME_DUPLICATE_ID_error'] = \
            NVME_DUPLICATE_ID_error
        logging.debug("Called check_NVME_ID, got NVME_DUPLICATE_ID_error=%s" +
            ", NVME_ID_dict=%s",
            NVME_DUPLICATE_ID_error, NVME_ID_dict)
        if NVME_DUPLICATE_ID_error:
            error_count += 1

        NVME_log_home_found = check_NVME_log_home(NVME_dict, min_loghome_size)
        logging.debug("Called check_NVME_log_home, got NVME_log_home_found=" +
                      "{}".format(NVME_log_home_found))

        if NVME_log_home_found or SSD_log_home_found:
            # All solid disk checks completed
            valid_drive_count += n_NVME_drives
            valid_drive_count += SSD_n_of_drives
            loghome_error = False
        else:
            loghome_error = True

    outputfile_segment_dict['NVME_drives'] = NVME_dict
    outputfile_segment_dict['NVME_ID'] = NVME_ID_dict
    outputfile_segment_dict['loghome_error'] = loghome_error
    if loghome_error:
        error_count += 1
        print("{0}{1} does not have any NVMe drive whose ".format(ERROR,
              LOCAL_HOSTNAME) + "capacity met the minimum {} ".format(
              min_loghome_size) + "Bytes log home size required")

    outputfile_segment_dict['ALL_number_of_drives'] = valid_drive_count
    if SAS_but_no_usable_drives:
        print("{0}{1} has supported SCSI controller[s] ".format(WARNING,
              LOCAL_HOSTNAME) + "but no proper device is attached " +
              "to it[them]")

    if SAS_fatal_error and NVME_error:
        error_count += 1
        print("{0}{1} has SCSI controller and NVMe drive ".format(ERROR,
              LOCAL_HOSTNAME) + "issues")
    if SSD_fatal_error and NVME_error:
        error_count += 1
        print("{0}{1} does not have any proper NVMe drive ".format(ERROR,
              LOCAL_HOSTNAME) + "or SSD can be used by ECE. At least " +
              "one NVMe drive or SSD is required")
    else:
        if valid_drive_count > max_drives:
            error_count += 1
            print("{0}{1} has a total of {2} storage ".format(ERROR,
                  LOCAL_HOSTNAME, valid_drive_count) + "devices that " +
                  "exceeds the maximum {} disks ".format(max_drives) +
                  "per node that ECE restricts")
        else:
            print("{0}{1} has a total of {2} disk[s] that ".format(INFO,
                  LOCAL_HOSTNAME, valid_drive_count) + "can be used " +
                  "by ECE")

    return error_count, outputfile_segment_dict


def check_WCE_SAS(SAS_drives_dict):
    # Check WCE is enabled, if so print an ERROR + return fatal_error True
    fatal_error = False
    num_errors = 0
    for drive in SAS_drives_dict.keys():
        enc_slot_list = drive.split(':')
        cmd = "{0} /call/e{1}/s{2} show all j".format(SAS_TOOL,
            enc_slot_list[0], enc_slot_list[1])
        try:
            if PYTHON3:
                storcli_output = subprocess.getoutput(cmd)
            else:
                storcli_output = commands.getoutput(cmd)
            wwn = WWNPATT.search(storcli_output).group('wwn')
            sasaddr = SASPATT.search(storcli_output).group('sasaddr')
            if wwn == 'NA':
                # if wwn is not defined, use sasaddr - we truncate last
                # digit later
                wwn = sasaddr
        except BaseException as e:
            sys.exit("{0}{1} cannot parse WWN for SAS devices by running cmd: {2}".
                format(ERROR, LOCAL_HOSTNAME, cmd) +
                " Hit exception: {}".format(e))
        SAS_drives_dict[drive].append(wwn.lower())
        map_error, os_device = map_WWN_to_OS_device(wwn.lower())
        logging.debug("Called map_WWN_to_OS_device got map_error=%s, os_device=%s",
            map_error, os_device)
        if map_error:  # We need to exit
            sys.exit("{0}{1} cannot map WWN({2}) to disk-kernel-name(/dev/sd*). ".
                format(ERROR, LOCAL_HOSTNAME, wwn.lower()) +
                "Please run cmd: {} and check files in /dev/disk/by-id/ ".
                format(cmd) + "for more info")
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
    print("{0}{1} is checking NIC".format(INFO, LOCAL_HOSTNAME))
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
        print("\t\tMemory: " + str(mem_gb) + " GiBytes")
        print("\t\tDIMM slots: " + str(num_dimms))
        print("\t\tDIMM slots in use: " + str(num_dimms - empty_dimms))
        scsi_ctrlr_cnt = len(SAS_model)
        if scsi_ctrlr_cnt == 1:
            print("\t\tSAS HBAs in use: {}".format(SAS_model[0]))
        elif scsi_ctrlr_cnt > 1:
            print("\t\tSAS HBAs in use: {}".format(SAS_model[0]))
            for i in range(1, scsi_ctrlr_cnt):
                print("\t\t                 {}".format(SAS_model[i]))
        print("\t\tJBOD SAS HDD drives: " + str(number_of_HDD_drives))
        print("\t\tJBOD SAS SSD drives: " + str(number_of_SSD_drives))
        print("\t\tHCAs in use: " + ', '.join(NIC_model))
    print("\t\tNVMe drives: " + str(number_of_NVME_drives))
    print("\t\tLink speed: " + str(device_speed))
    print("\t\tRun ended at " + str(end_time_date))
    print("")
    print("{0}{1} saved detailed information of this instance ".format(INFO,
          LOCAL_HOSTNAME) + "to {}".format(outputfile_name))

    if sata_on:
        print("{0}{1} has run SATA check but using ".format(WARNING,
              LOCAL_HOSTNAME) + "SATA device for ECE is NOT recommended")
    if nfatal_errors > 0:
        sys.exit("{0}{1} cannot run IBM Storage Scale ".format(ERROR,
                 LOCAL_HOSTNAME) + "Erasure Code Edition")
    elif all_checks_on:
        print("{0}{1} can run IBM Storage Scale Erasure Code ".format(INFO,
              LOCAL_HOSTNAME) + "Edition")
    else:
        print("{0}{1} Not all checks were enabled. The ".format(WARNING,
              LOCAL_HOSTNAME) + "precheck tool can NOT claim this " +
              "system could run ECE")


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
    logging.debug("Going to check if all tests are enabled")
    if (cpu_check and md5_check and mem_check and os_check and packages_ch
            and storage_check and net_check):
        all_checks_on = True
        logging.debug("All tests are enabled")
    else:
        all_checks_on = False
        logging.debug("Not all tests are enabled")

    if sata_on:
        logging.debug("SATA checks are enabled")
        print("{0}{1} enables SATA check. However, it is ".format(WARNING,
              LOCAL_HOSTNAME) + "not recommended to use SATA device " +
              "for ECE")
    else:
        logging.debug("SATA checks are not enabled")

    # Check if input IP is a local IP
    ip_dev_dict = map_ipv4_to_local_interface(ip_address)
    logging.debug("Called map_ipv4_to_local_interface, got ip_dev_dict=%s",
        ip_dev_dict)
    if not ip_dev_dict[ip_address]:
        sys.exit(1)

    # JSON loads and calculate and store MD5
    logging.debug("Going to load the JSON files")
    os_dictionary = load_json(path + "supported_OS.json")
    packages_dictionary = load_json(path + "packages.json")
    SAS_dictionary = load_json(path + "SAS_adapters.json")
    NIC_dictionary = load_json(path + "NIC_adapters.json")
    HW_dictionary = load_json(path + "HW_requirements.json")
    logging.debug("JSON files loaded")
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

    min_loghome_size = 0
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
    logging.debug("Parameters of this run written")

    # Check root
    logging.debug("Going to check if we are root")
    check_root_user()
    logging.debug("root check passed")

    # Check cpu
    logging.debug("Starting CPU checks")
    current_processor = "NOT CHECKED"
    num_sockets = 0
    core_count = 0
    if cpu_check:
        logging.debug("CPU check is enabled")
        logging.debug("Going to call check_processor()")
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
    logging.debug("Going to check the RedHat Linux distribution")
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
        logging.debug("Check required packages")
        print("{0}{1} is checking package required by this tool".format(
              INFO, LOCAL_HOSTNAME))
        packages_errors = package_check(packages_dictionary)
        if packages_errors > 0:
            logging.debug("Got number of unexpected package status: %s",
                packages_errors)
            sys.exit("{0}{1} has {2} unexpected package installation ".
                format(ERROR, LOCAL_HOSTNAME, packages_errors) +
                "status[es]")
        else:
            logging.debug(
                "Passed required packages check"
            )
            outputfile_dict['packages_checked'] = packages_dictionary

    # Get node serial number
    logging.debug("Going to get node serial number")
    fatal_error, system_serial = get_system_serial()
    if fatal_error:
        logging.debug("We got an error from quering the system serial")
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
        logging.debug("Going to perform the memory checks")
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

    virt_type = detect_virtualization()
    logging.debug("Called detect_virtualization, got virt_type=%s", virt_type)
    if virt_type not in ('vmware', 'none'):
        sys.exit(1)
    if virt_type == 'vmware':
        SAS_model = []
        n_HDD_drives = 0
        n_SSD_drives = 0
        n_NVME_drives = 0
        if storage_check:
            error_count, outputfile_stor_dict = \
                check_vmware_storage(SAS_dictionary, min_loghome_size,
                    max_drives, packages_ch, sata_on)
            logging.debug("Called check_vmware_storage, got error_count=%s, " +
                "outputfile_stor_dict=%s", error_count, outputfile_stor_dict)
            nfatal_errors += error_count
            SAS_model = []
            n_HDD_drives = 0
            n_SSD_drives = 0
            n_NVME_drives = 0
            if outputfile_stor_dict:
                for key, val in outputfile_stor_dict.items():
                    outputfile_dict[key] = val
                try:
                    SAS_model = outputfile_stor_dict['SAS_model']
                    n_HDD_drives = outputfile_stor_dict['HDD_n_of_drives']
                    n_SSD_drives = outputfile_stor_dict['SSD_n_of_drives']
                    n_NVME_drives = outputfile_stor_dict['NVME_number_of_drives']
                except KeyError as e:
                    logging.debug("Tried to extract SAS_model or n_HDD_drives or " +
                                  "n_NVME_drives but hit KeyError: %s", e)
            else:
                nfatal_errors += 1
                print("{0}{1} cannot generate storage part of outputfile dict".
                    format(ERROR, LOCAL_HOSTNAME))
    else:
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
                NVME_error, n_NVME_drives = get_nvme_drive_num()
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
                    logging.debug("Going to check WCE on NVMe")
                    NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
                    outputfile_dict['NVME_WCE_error'] = NVME_WCE_error
                    if NVME_WCE_error:
                        nfatal_errors = nfatal_errors + 1
                    # All LBA NVME the same check
                    logging.debug("Going to check LBA on NVMe")
                    NVME_LBA_error = check_LBA_NVME(NVME_dict)
                    logging.debug(
                        "Got back from check_LBA_NVME with NVME_LBA_error=" +
                        str(NVME_LBA_error)
                    )
                    outputfile_dict['NVME_LBA_error'] = NVME_LBA_error
                    if NVME_LBA_error:
                        nfatal_errors = nfatal_errors + 1
                    # Metadata NVME check
                    logging.debug("Going to check MD on NVMe")
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
                    logging.debug("We found issues on SAS and NVMe checks")
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
                SAS_fatal_error, check_disks, SAS_model = check_scsi_controller(
                                                              SAS_dictionary)
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
                        "We have disks to check, first we check the SAS packages")
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
                        logging.debug("Going to start HDD tests")
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
                            logging.debug("Going to check WCE on HDD")
                            print("{0}{1} is checking WCE setting of HDD".format(INFO,
                                  LOCAL_HOSTNAME))
                            HDD_WCE_error, HDD_dict = check_WCE_SAS(HDD_dict)
                            logging.debug("Got HDD_WCE_error={}".format(HDD_WCE_error))
                            outputfile_dict['HDD_WCE_error'] = HDD_WCE_error
                            if HDD_WCE_error:
                                nfatal_errors = nfatal_errors + 1
                        logging.debug("Going to start SDD tests")
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
                            logging.debug("Going to check WCE on SSD")
                            print("{0}{1} is checking WCE setting of SSD".format(INFO,
                                  LOCAL_HOSTNAME))
                            SSD_WCE_error, SSD_dict = check_WCE_SAS(SSD_dict)
                            logging.debug("Got SSD_WCE_error={}".format(SSD_WCE_error))
                            outputfile_dict['SSD_WCE_error'] = SSD_WCE_error
                            if SSD_WCE_error:
                                nfatal_errors = nfatal_errors + 1
                            logging.debug(
                                "Going to check for SSD big enough for loghome"
                            )
                            SSD_log_home_pres = check_SSD_loghome(SSD_dict, min_loghome_size)

                        if not HDD_error:
                            n_mestor_drives = n_mestor_drives + n_HDD_drives
                            if n_HDD_drives == 1:
                                print("{0}{1} has {2} SAS HDD can be used by ECE".format(INFO,
                                      LOCAL_HOSTNAME, n_HDD_drives))
                            else:
                                print("{0}{1} has {2} SAS HDDs can be used by ".format(INFO,
                                      LOCAL_HOSTNAME, n_HDD_drives) + "ECE")
                        if not SSD_error:
                            n_mestor_drives = n_mestor_drives + n_SSD_drives
                            if n_SSD_drives == 1:
                                print("{0}{1} has {2} SAS SSD can be used by ECE".format(INFO,
                                      LOCAL_HOSTNAME, n_SSD_drives))
                            else:
                                print("{0}{1} has {2} SAS SSDs can be used by ECE".format(
                                      INFO, LOCAL_HOSTNAME, n_SSD_drives))
                        logging.debug("Got {0} HDD and {1} SSD can be used by ECE".format(
                                      n_HDD_drives, n_SSD_drives))
                        if HDD_error and SSD_error:
                            logging.debug("Localhost has SCSI controller but no device " +
                                          " can be used by ECE")
                            SAS_but_no_usable_drives = True
                            outputfile_dict['found_SAS_card_but_no_drives'] = True
                # NVME checks
                logging.debug("Going to start NVMe tests")
                NVME_error, n_NVME_drives = get_nvme_drive_num()
                logging.debug(
                    "Got back from check_NVME with NVME_error=" +
                    str(NVME_error) +
                    " and n_NVME_drives=" +
                    str(n_NVME_drives)
                )
                outputfile_dict['NVME_fatal_error'] = NVME_error
                outputfile_dict['NVME_number_of_drives'] = n_NVME_drives
                if not NVME_error:
                    logging.debug("Going to check for NVMe packages")
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
                    logging.debug("Going to check WCE on NVMe")
                    NVME_WCE_error, NVME_dict = check_WCE_NVME(NVME_dict)
                    logging.debug(
                        "Got back from check_WCE_NVME with NVME_WCE_error=" +
                        str(NVME_WCE_error)
                    )
                    outputfile_dict['NVME_WCE_error'] = NVME_WCE_error
                    if NVME_WCE_error:
                        nfatal_errors = nfatal_errors + 1
                    # All LBA NVME the same check
                    logging.debug("Going to check LBA on NVMe")
                    NVME_LBA_error = check_LBA_NVME(NVME_dict)
                    logging.debug(
                        "Got back from check_LBA_NVME with NVME_LBA_error=" +
                        str(NVME_LBA_error)
                    )
                    outputfile_dict['NVME_LBA_error'] = NVME_LBA_error
                    if NVME_LBA_error:
                        nfatal_errors = nfatal_errors + 1
                    # Metadata NVME check
                    logging.debug("Going to check MD on NVMe")
                    NVME_MD_error = check_MD_NVME(NVME_dict)
                    logging.debug(
                        "Got back from check_MD_NVME with NVME_MD_error=" +
                        str(NVME_MD_error)
                    )
                    outputfile_dict['NVME_MD_error'] = NVME_MD_error
                    if NVME_MD_error:
                        nfatal_errors = nfatal_errors + 1
                    #check nguid and euid of nvmes drives for uniqueness
                    logging.debug("Going to check NVMe ID uniqueness")
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

                    logging.debug("Going to check for NVMe big enough for loghome")
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
                    logging.debug("We have a supported SAS card but no usable drives")
                    print(
                        WARNING +
                        LOCAL_HOSTNAME +
                        " has a supported SAS adapter but no supported drives")
                # Lets check what we can use here
                if SAS_fatal_error and NVME_error:
                    logging.debug("We found issues on SAS and NVMe checks")
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has found issues with SAS adapter and NVMe  " +
                        "devices in this system")
                    nfatal_errors = nfatal_errors + 1
                if SSD_error and NVME_error:
                    logging.debug("There is no non-rotational device in this host")
                    print(
                        ERROR +
                        LOCAL_HOSTNAME +
                        " has no SSD or NVMe device that ECE can use. At least " +
                        "one device of those types is required to run ECE")
                    nfatal_errors = nfatal_errors + 1
                else:
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
                        print("{0}{1} has a total of {2} storage ".format(INFO,
                              LOCAL_HOSTNAME, n_mestor_drives) + "devices can " +
                              "be used by ECE")

    # Network checks
    if virt_type == 'vmware':
        outputfile_dict['local_hostname'] = LOCAL_HOSTNAME
        outputfile_dict['IP_address_is_possible'] = True
        outputfile_dict['ip_address'] = ip_address
        NIC_model = []
        device_speed = 'NOT CHECKED'
        if net_check:
            error_count, outputfile_nic_dict = \
                check_vmware_nic(ip_dev_dict, net_check, NIC_dictionary,
                    min_link_speed)
            logging.debug("Called check_vmware_nic, got error_count=%s, " +
                "outputfile_nic_dict=%s", error_count, outputfile_nic_dict)
            nfatal_errors += error_count
            if not outputfile_nic_dict:
                nfatal_errors += 1
                print("{0}{1} cannot generate network part of outputfile dict".
                    format(ERROR, LOCAL_HOSTNAME))
            else:
                for key, val in outputfile_nic_dict.items():
                    outputfile_dict[key] = val
                try:
                    NIC_model = outputfile_nic_dict['NIC_model']
                    device_speed = outputfile_nic_dict['netdev_speed']
                except KeyError as e:
                    logging.debug("Tried to extract NIC_model or netdev_speed. " +
                        "Hit KeyError: %s", e)
    else:
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
            logging.debug("Going to check NIC model")
            fatal_error, NIC_model = check_NIC(NIC_dictionary,ip_address)
            logging.debug(
                "Got back from check_NIC with fatal_error=" +
                str(fatal_error) +
                " and NIC_model=" +
                str(NIC_model))
            outputfile_dict['error_NIC_card'] = fatal_error
            outputfile_dict['NIC_model'] = NIC_model
            if fatal_error:
                nfatal_errors = nfatal_errors + 1
            elif ip_address_is_IP:
                logging.debug("Check if {} corresponds to a device ".format(
                              ip_address) + "and its link speed")
                print("{0}{1} is checking device name of {2} and ".format(INFO,
                      LOCAL_HOSTNAME, ip_address) + "its speed")
                net_devices = list_net_devices()
                outputfile_dict['ALL_net_devices'] = net_devices
                fatal_error, net_interface = what_interface_has_ip(
                    net_devices, ip_address)
                logging.debug(
                    "Got back from what_interface_has_ip with fatal_error=" +
                    str(fatal_error) +
                    " and net_interface=" +
                    str(net_interface))
                outputfile_dict['IP_not_found'] = fatal_error
                outputfile_dict['netdev_with_IP'] = net_interface
                if fatal_error:
                    nfatal_errors = nfatal_errors + 1
                else:
                    # It is a valid IP and there is an interface on this node with
                    # this IP
                    fatal_error, device_speed = get_network_interface_speed(
                        net_interface, min_link_speed)
                    logging.debug(
                        "Got back from get_network_interface_speed with fatal_error=" +
                        str(fatal_error) +
                        " and link speed of " +
                        str(device_speed)
                    )
                    outputfile_dict['netdev_speed_error'] = fatal_error
                    outputfile_dict['netdev_speed'] = device_speed
                    if fatal_error:
                        nfatal_errors = nfatal_errors + 1
            else:
                logging.debug("The IP is not a valid one")
                print(
                    ERROR +
                    LOCAL_HOSTNAME +
                    " " +
                    ip_address +
                    " is not a valid IP address")
                nfatal_errors = nfatal_errors + 1

    # Check tuned
    if tuned_check:
        logging.debug("Check tuned profile")
        print("{0}{1} is checking tuned profile".format(INFO, LOCAL_HOSTNAME))
        rc = check_tuned_profile()
        if rc != 0:
            fatal_error = True
        logging.debug("Got rc={} after called check_tuned_profile".format(rc))
        if fatal_error:
            nfatal_errors += 1
            outputfile_dict['tuned_fail'] = True
        else:
            outputfile_dict['tuned_fail'] = False

    # Check py3 YAML
    logging.debug("Going to check for py3_yaml")
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
    lspci_dict = {}
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
    outputdata = json.dumps(outputfile_dict, indent=4)
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
