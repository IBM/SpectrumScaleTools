"""This module checks if local system could run ECE.
"""
import os
import logging
import sys
import json
import datetime
import subprocess
import platform
import argparse
import hashlib
import re
import shlex

from typing import Any, Tuple, Dict, List

# This Module version
MODULE_VER = "2.10"

# GIT URLs
GITREPOURL = "https://github.com/IBM/SpectrumScaleTools"
TUNED_TOOL = "ece_tuned_profile in https://github.com/IBM/SpectrumScaleTools"
STOR_TOOL = "ece_storage_readiness in https://github.com/IBM/SpectrumScaleTools"

# Colorful constants
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESETCOL = "\033[0m"

HOSTNAME = platform.node().split('.', 1)[0]

# Message labels
INFO = f"[ {GREEN}INFO{RESETCOL}  ] {HOSTNAME}"
WARN = f"[ {YELLOW}WARN{RESETCOL}  ] {HOSTNAME}"
ERROR = f"[ {RED}FATAL{RESETCOL} ] {HOSTNAME}"

# Set MegaRAID Storage Manager tool as strocli64 or perccli64(Dell machine)
MSM_NAME = ""
MSM_APP = ""

# Define expected MD5 checksums of json files
MD5CKSUM_KV = {
    'HW_requirements.json': 'a0e12e5bd9e0ddd2c8d6471c5ba78fe2',
    'NIC_adapters.json': 'dca06f75452f45c65658660fb8e969e6',
    'packages.json': '27954578df4a1673ef5599af7609e0fe',
    'SAS_adapters.json': '36b54f83786e2529b63c6c9b44a2cb6e',
    'supported_OS.json': '9b7c8cb13784472f43e36df20249119f'
}

# (SAS Controller) Device Interface type in output of MegaRAID tool
OK_DEVIF_TYPE = 'SAS-12G'

# Compatible tuned profiles
COMPATIBLE_TUNEDS = ['spectrumscale-ece', 'storagescale-ece']

log = None

def set_logger(
        logdir: str,
        logfile: str,
        isverbose=False) -> Any:
    """Set logger.
    Args:
        logdir: directory to save log file.
        logfile: log file.
        isverbose: Print verbose message if set True. Default is False.
    Returns:
        logger object.
    """
    errcnt = 0
    if not logdir or isinstance(logdir, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter logdir: {logdir}")
    if not logfile or isinstance(logfile, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter logfile: {logfile}")
    if isinstance(isverbose, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter isverbose: {isverbose}")
    if errcnt != 0:
        print('')
        sys.exit(1)

    if os.path.isdir(logdir) is False:
        try:
            os.makedirs(logdir)
        except BaseException as e:
            sys.exit(f"{ERROR} tried to create {logdir} but hit exception: " +
                     f"{e}\n")

    log_path = os.path.join(logdir, logfile)
    log_fmt = '%(asctime)s [%(levelname).1s] [line: %(lineno)d] %(message)s'
    logging.basicConfig(
        level=logging.DEBUG,
        format=log_fmt,
        filename=log_path,
        filemode='w')

    console = logging.StreamHandler()
    if isverbose is True:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(log_fmt))
    logging.getLogger('').addHandler(console)
    logger = logging.getLogger(__name__)
    return logger


def parse_arguments() -> Tuple[str, ...]:
    """Parse input arguments
    Args:
    Returns:
        (ip_addr, path, fips, check_md5, check_cpu, check_os, check_pkg,
         check_mem, check_stor, check_net, check_tuned, toolkit, check_sata,
         isverbose)
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--ip',
        required=True,
        action='store',
        dest='ip_addr',
        help='local IPv4 for NSD (Network Shared Disks)',
        metavar='IPv4_ADDRESS',
        type=str,
        default="NO IP")

    parser.add_argument(
        '--path',
        action='store',
        dest='path',
        help='where json files are located. Default is current directory',
        metavar='PATH',
        type=str,
        default='./')

    parser.add_argument(
        '--FIPS',
        action='store_true',
        dest='fips',
        help='run this tool with FIPS (Federal Information Processing ' +
        'Standards) mode. The FIPS mode cannot be used for acceptance',
        default=False)

    parser.add_argument(
        '--no-md5-check',
        action='store_false',
        dest='check_md5',
        help='skip JSON file check',
        default=True)

    parser.add_argument(
        '--no-cpu-check',
        action='store_false',
        dest='check_cpu',
        help='skip CPU check',
        default=True)

    parser.add_argument(
        '--no-os-check',
        action='store_false',
        dest='check_os',
        help='skip OS check',
        default=True)

    parser.add_argument(
        '--no-pkg-check',
        action='store_false',
        dest='check_pkg',
        help='skip required package check',
        default=True)

    parser.add_argument(
        '--no-mem-check',
        action='store_false',
        dest='check_mem',
        help='skip memory check',
        default=True)

    parser.add_argument(
        '--no-stor-check',
        action='store_false',
        dest='check_stor',
        help='skip storage check',
        default=True)

    parser.add_argument(
        '--no-net-check',
        action='store_false',
        dest='check_net',
        help='skip network check',
        default=True)

    parser.add_argument(
        '--no-tuned-check',
        action='store_false',
        dest='check_tuned',
        help='skip tuned check',
        default=True)

    parser.add_argument(
        '--allow-sata',
        action='store_true',
        dest='check_sata',
        help='EXPERIMENTAL: Check SATA storage device',
        default=False)

    parser.add_argument(
        '--toolkit',
        action='store_true',
        dest='toolkit',
        help='use this option when IBM Storage Scale install-toolkit runs ' +
        'the tool',
        default=False)

    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version='IBM Storage Scale Erasure Code Edition (ECE) readiness OS ' +
        f"readiness version: {MODULE_VER}")

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        dest='isverbose',
        help='show debug messages on console',
        default=False)

    args = parser.parse_args()

    try:
        json_dir = os.path.normpath(args.path)
    except BaseException as e:
        sys.exit(f"{ERROR} tried to normalize path: {args.path} but hit " +
                 f"exception: {e}\n")

    return (args.ip_addr, json_dir, args.fips, args.check_md5, args.check_cpu,
            args.check_os, args.check_pkg, args.check_mem, args.check_stor,
            args.check_net, args.check_tuned, args.check_sata, args.toolkit,
            args.isverbose)


def is_ipv4(ipv4: str) -> bool:
    """Is the input string IPv4 format?
    Args:
        ipv4: string of an IP address.
    Returns:
        True if input ipv4 is a correct format, else, False.
    """
    if not ipv4 or isinstance(ipv4, str) is False:
        print(f"{ERROR} Invalid parameter ipv4: {ipv4}")
        return False

    ipv4_segs = ipv4.split('.')
    ipv4_seg_num = len(ipv4_segs)
    if ipv4_seg_num != 4:
        print(f"{ERROR} {ipv4} is an invalid IPv4 format")
        return False

    for seg in ipv4_segs:
        if seg.isdigit() is not True:
            log.debug("%s has incorrect segment: %s", ipv4, seg)
            print(f"{ERROR} {ipv4} contains non-numeric segment")
            return False
        digit_seg = -1
        try:
            digit_seg = int(seg)
        except ValueError as e:
            log.debug("Tried to convert %s to integer but hit ValueError: %s",
                      seg, e)
            print(f"{ERROR} hit exception while converting {seg} to integer")
            return False

        if digit_seg < 0 or digit_seg > 255:
            log.debug("Segment %s in %s is out of range", seg, ipv4)
            print(f"{ERROR} IPv4 {ipv4} is invalid")
            return False

    log.debug("IPv4 %s is valid", ipv4)
    return True


def runcmd(
        cmd: str,
        ignore_exception: bool=False) -> Tuple[str, str, int]:
    """Run shell command.
    Args:
        cmd: command string.
        ignore_exception: [Optional] default is False.
           False, print message and exit if hit exception.
           True, translate exception to string and push it to stderr.
    Returns:
        (stdout, stderr, returncode)
    """
    if not cmd or isinstance(cmd, str) is False:
        if ignore_exception is True:
            return '', f"Invalid cmd: {cmd}", 1
        raise ValueError("Invalid parameter: cmd")

    stdout = ''
    stderr = 'Error'
    rc = 1
    try:
        proc = subprocess.Popen(
                   shlex.split(cmd),
                   stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,
                   stdin=None)
        stdout, stderr = proc.communicate()
        rc = proc.returncode
    except BaseException as e:
        if ignore_exception is True:
            return '', f"{e}", 1
        raise e

    if isinstance(stdout, bytes):
        stdout = stdout.decode()
    if isinstance(stderr, bytes):
        stderr = stderr.decode()

    return str(stdout), str(stderr), int(rc)


def get_ip_of_ifname(netif_name: str) -> str:
    """Extract the IP address of input network interface name.
    Args:
        netif_name: network controller logical name (network interface).
    Returns:
        IP address if succeeded. Else, ''.
    """
    if not netif_name or isinstance(netif_name, str) is False:
        print(f"{ERROR} Invalid parameter netif_name: {netif_name}")
        return ''

    errcnt = 0
    netif_name = netif_name.split('@')[0]
    cmd = f"ip addr show {netif_name}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        errcnt += 1
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while showing IP address of {netif_name}")
    if rc != 0:
        errcnt += 1
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while showing IP address of {netif_name}")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)

    if rc == 0 and not out.strip():
        errcnt += 1
        print(f"{WARN} got empty stdout while showing IP address of " +
              f"{netif_name}")
    if errcnt != 0:
        return ''

    lines = out.strip().splitlines()
    inet_ip = ''
    for line in lines:
        if 'inet' in line and 'inet6' not in line:
            try:
                inet_ip = line.split()[1].split('/')[0].strip()
            except BaseException as e:
                log.debug("Tried to extract IP address from %s but hit "
                          "exception: %s", line, e)
                print(f"{ERROR} hit exception while extracting IP address of " +
                      f"{netif_name}")
        if inet_ip:
            break
    if inet_ip:
        log.debug("IP address of %s is %s", netif_name, inet_ip)
    else:
        log.debug("%s does not have an IP address", netif_name)
    return inet_ip


def map_active_netif_to_ip() -> Dict[str, str]:
    """Map the active network interface to IP Address.
    Args:
    Returns:
        {logicalName: IP, ...} if succeeded. Else, {}.
        E.g., {'lo': '127.0.0.1', ...}
    """
    errcnt = 0
    cmd = 'ip addr'
    out = ''
    err = ''
    rc = 1
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        errcnt += 1
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while showing IP address")
    if rc != 0:
        errcnt += 1
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while showing IP address")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)

    if rc == 0 and not out.strip():
        errcnt += 1
        print(f"{WARN} got empty stdout while showing IP address")
    if errcnt != 0:
        return {}

    lines = out.strip().splitlines()
    lgnm_ip_kv = {}
    lgc_names = []
    for line in lines:
        lgc_name = ''
        line = line.strip()
        if 'UP,LOWER_UP' in line and 'state UP' in line:
            try:
                lgc_name = line.split(':')[1].strip()
            except BaseException as e:
                log.debug("Tried to extract active network interface name from "
                          "%s but hit exception: %s", line, e)
                print(f"{WARN} hit exception while extracting active network " +
                      "interface name")
        if lgc_name:
            lgc_names.append(lgc_name)
    log.debug("Got active net if logical names: %s", lgc_names)
    if not lgc_names:
        print(f"{ERROR} cannot extract any active network interface name")
        return {}

    for lgnm in lgc_names:
        ip = get_ip_of_ifname(lgnm)
        if ip:
            lgnm_ip_kv[lgnm] = ip

    log.debug("Mapped net logical name to IP, got: %s", lgnm_ip_kv)
    if not lgnm_ip_kv:
        print(f"{ERROR} has no active network interface or no IP address is " +
              "set to any active network interface")
    return lgnm_ip_kv


def load_json(filepath: str) -> Dict[str, str]:
    """Translate the content of the input json file to KV pair.
    Args:
        filepath: file path
    Returns:
        KV pair translated from input file. Else, {}.
    """
    warncnt = 0
    if not filepath or isinstance(filepath, str) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter filepath: {filepath}")
    if os.path.isfile(filepath) is False:
        warncnt += 1
        print(f"{WARN} {filepath} is not a file")
    if warncnt != 0:
        return {}
    kv = {}
    try:
        with open(filepath, mode="r", encoding="utf-8") as fh:
            kv = json.load(fh)
    except BaseException as e:
        log.debug("Tried to load %s but hit exception: %s", filepath, e)
        print(f"{WARN} hit exception while parsing {filepath}")
        return {}
    log.debug("Translated content of %s. Got %s", filepath, kv)
    if not kv:
        print(f"{WARN} got empty KV pair from {filepath}")
    return kv


def get_md5_cksum(filepath: str) -> str:
    """Calculate the MD5 checksum of the input file path.
    Args:
        filepath: file path.
    Returns:
        md5 checksum of file if succeeded. Else, 'Unknown'.
    """
    if not filepath or isinstance(filepath, str) is False:
        print(f"{WARN} Invalid parameter filepath: {filepath}")
        return 'Unknown'
    if os.path.isfile(filepath) is False:
        print(f"{ERROR} {filepath} is not a file")
        return 'Unknown'
    md5_cksum = ''
    try:
        with open(filepath, mode="rb") as fh:
            data = fh.read()
            md5_hash = hashlib.md5(data)
            md5_cksum = md5_hash.hexdigest()
    except BaseException as e:
        log.debug("Tried to calculate MD5 cksum of %s but hit exception: %s",
                  filepath, e)
        print(f"{ERROR} hit excpetion while calculating MD5 checksum of " +
              f"{filepath}")
        return 'Unknown'
    if not md5_cksum:
        md5_cksum = 'Unknown'
        print(f"{ERROR} cannot calculate MD5 checksum of {filepath}")
    log.debug("Got %s %s", md5_cksum, filepath)
    return md5_cksum


def verify_file_checksum(file_md5_kv: Dict) -> Tuple[int, Dict]:
    """Verify if the file has not been modified.
    Args:
        file_md5_kv: {fileName: calcMd5cksum,...}.
    Returns:
        (errcnt, md5_stat_kv)
    """
    if not file_md5_kv or isinstance(file_md5_kv, dict) is False:
        print(f"{ERROR} Invalid parameter file_md5_kv: {file_md5_kv}")
        return 1, {}

    log.debug("Verify MD5 checksum of json files")
    errcnt = 0
    md5_stat_kv = {}
    for key, val in file_md5_kv.items():
        expe_md5 = ''
        try:
            expe_md5 = MD5CKSUM_KV[key]
        except KeyError as e:
            errcnt += 1
            log.debug("Tried to extract expected md5 checksum value of %s but "
                      "hit KeyError: %s", key, e)
            print(f"{ERROR} hit exception while extracting expected MD5 " +
                  f"checksum of {key}")
            continue
        if not expe_md5:
            errcnt += 1
            log.debug("Got empty expected MD5 checksum of %s", key)
            print(f"{ERROR} got empty expected MD5 checksum of {key}")
            continue
        if val == expe_md5:
            md5_stat_kv[key] = True
        else:
            errcnt += 1
            md5_stat_kv[key] = False
            log.debug("%s has MD5: %s", key, val)
            log.debug("But its expectation MD5 is %s", expe_md5)
            print(f"{ERROR} MD5 checksum of {key} is NOT as expected. The " +
                  "file is unreliable")
    log.debug("Got errcnt: %s, md5_stat_kv: %s", errcnt, md5_stat_kv)

    return errcnt, md5_stat_kv


def get_json_versions(
        os_kv: Dict,
        pkg_kv: Dict,
        scsi_ctrlr_kv: Dict,
        nic_kv: Dict,
        hw_kv: Dict) -> Dict[int, Dict]:
    """Extract file-version KV pair from input KV pairs.
    Args:
        os_kv:
        pkg_kv:
        scsi_ctrlr_kv:
        nic_kv:
        hw_kv:
    Returns:
        (errcnt, ver_kv)
    """
    errcnt = 0
    if not os_kv or isinstance(os_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter os_kv: {os_kv}")
    if not pkg_kv or isinstance(pkg_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pkg_kv: {pkg_kv}")
    if not scsi_ctrlr_kv or isinstance(scsi_ctrlr_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter scsi_ctrlr_kv: {scsi_ctrlr_kv}")
    if not nic_kv or isinstance(nic_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter nic_kv: {nic_kv}")
    if not hw_kv or isinstance(hw_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter hw_kv: {hw_kv}")
    if errcnt != 0:
        return errcnt, {}

    os_kv_ver = {}
    pkg_kv_ver = {}
    scsi_ctrlr_kv_ver = {}
    nic_kv_ver = {}
    hw_kv_ver = {}
    try:
        os_kv_ver = os_kv['json_version']
    except KeyError as e:
        errcnt += 1
        log.debug("Tried to extract json_version from %s but hit KeyError: %s",
                  os_kv, e)
        print(f"{ERROR} hit exception while extracting json file version of " +
              "supported OS")
    try:
        pkg_kv_ver = pkg_kv['json_version']
    except KeyError as e:
        errcnt += 1
        log.debug("Tried to extract json_version from %s but hit KeyError: %s",
                  pkg_kv, e)
        print(f"{ERROR} hit exception while extracting json file version of " +
              "required packages")
    try:
        scsi_ctrlr_kv_ver = scsi_ctrlr_kv['json_version']
    except KeyError as e:
        errcnt += 1
        log.debug("Tried to extract json_version from %s but hit KeyError: %s",
                  scsi_ctrlr_kv, e)
        print(f"{ERROR} hit exception while extracting json file version of " +
              "supported SCSI controllers")
    try:
        nic_kv_ver = nic_kv['json_version']
    except KeyError as e:
        errcnt += 1
        log.debug("Tried to extract json_version from %s but hit KeyError: %s",
                  nic_kv, e)
        print(f"{ERROR} hit exception while extracting json file version of " +
              "supported Network Interface Cards")
    try:
        hw_kv_ver = hw_kv['json_version']
    except KeyError as e:
        errcnt += 1
        log.debug("Tried to extract json_version from %s but hit KeyError: %s",
                  hw_kv, e)
        print(f"{ERROR} hit exception while extracting json file version of " +
              "hardware requirements")

    ver_kv = {}
    ver_kv['supported_OS'] = str(os_kv_ver)
    ver_kv['packages'] = str(pkg_kv_ver)
    ver_kv['SAS_adapters'] = str(scsi_ctrlr_kv_ver)
    ver_kv['NIC_adapters'] = str(nic_kv_ver)
    ver_kv['HW_requirements'] = str(hw_kv_ver)
    log.debug("Got errcnt: %s, ver_kv: %s", errcnt, ver_kv)
    return errcnt, ver_kv


def show_header(
        module_ver: str,
        toolkit: bool,
        json_ver_kv: Dict) -> None:
    """Show the header of the output of this script.
    Args:
        module_ver: OS readiness tool version.
        toolkit: for install toolkit only.
        json_ver_kv: versions of configuration files.
    Returns:
    """
    if not module_ver or isinstance(module_ver, str) is False:
        log.debug("Invalid parameter module_ver: %s", module_ver)
        print(f"{INFO} IBM Storage Scale Erasure Code Edition (ECE) OS " +
              "readiness version: Unknown")
    else:
        print(f"{INFO} IBM Storage Scale Erasure Code Edition (ECE) OS " +
              f"readiness version: {module_ver}")

    if isinstance(toolkit, bool) is False:
        log.debug("Invalid parameter toolkit: %s", toolkit)
    elif toolkit is False:
        print(f"{INFO} This precheck tool with absolutely no warranty")
        print(f"{INFO} For more information, please check {GITREPOURL}")

    os_ver = 'Unknown'
    pkg_ver = 'Unknown'
    scsi_ctrlr_ver = 'Unknown'
    nic_ver = 'Unknown'
    hw_ver = 'Unknown'
    if not json_ver_kv or isinstance(json_ver_kv, dict) is False:
        log.debug("Invalid parameter json_ver_kv: %s", json_ver_kv)
    else:
        # Renew versions
        try:
            os_ver = json_ver_kv['supported_OS']
            pkg_ver = json_ver_kv['packages']
            scsi_ctrlr_ver = json_ver_kv['SAS_adapters']
            nic_ver = json_ver_kv['NIC_adapters']
            hw_ver = json_ver_kv['HW_requirements']
        except KeyError as e:
            log.debug("Tried to extract version items from %s but hit "
                      "KeyError: %s", json_ver_kv, e)
            print(f"{WARN} hit exception while extracting json file version")

    print(f"{INFO} JSON file versions:")
    print(f"{INFO} \tsupported OS: \t\t{os_ver}")
    print(f"{INFO} \tpackages: \t\t{pkg_ver}")
    print(f"{INFO} \tSAS adapters: \t\t{scsi_ctrlr_ver}")
    print(f"{INFO} \tNIC adapters: \t\t{nic_ver}")
    print(f"{INFO} \tHW requirements: \t{hw_ver}")


def check_root_user() -> bool:
    """Check if current user is 'root'.
    Args:
    Returns:
        True if current user is root. Else, False.
    """
    # uid=0(root) gid=0(root) groups=0(root)
    effective_uid = os.getuid()
    is_root = False
    if effective_uid == 0:
        is_root = True
        log.debug("This tool is running with 'root' user")
        print(f"{INFO} is running with 'root' user")
    else:
        log.debug("This tool is not running with 'root' user")
        print(f"{ERROR} this tool needs to be run with 'root' user")
    return is_root


def detect_virtualization() -> str:
    """Detect the virtualization of current system.
    Args:
    Returns:
        'error' if hit error. Else, output of command: systemd-detect-virt.
        'vmware' if OS was running on VMware.
        'none' if OS was running on physical machine.
    """
    cmd = 'systemd-detect-virt'
    out, err, rc = runcmd(cmd, True)
    if rc != 0:
        # rc is 1, stdout is 'none', means physical environment
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
    if not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{ERROR} cannot query system virtual type")
        return 'error'
    virt_type = out.strip()
    if virt_type == 'none':
        pass
    elif virt_type == 'vmware':
        name = ''
        pdt_cmd = 'cat /sys/class/dmi/id/product_name'
        name, _, _ = runcmd(pdt_cmd, True)
        name = name.strip()
        if name:
            print(f"{INFO} is {name} virtual machine")
    else:
        log.debug("Got system virtualization type: %s", virt_type)
        print(f"{ERROR} is {virt_type} virtual machine which is not verified " +
              "to support ECE")
    return virt_type


def check_processor() -> str:
    """Check system processor name.
    Args:
    Returns:
        processor name if succeeded. Else, 'Unknown'.
    """
    print(f"{INFO} is checking system processor")
    proc_name = 'unknown'
    try:
        proc_name = platform.processor()
    except BaseException as e:
        log.debug("Tried to get processor name but hit exception: %s", e)
        print(f"{ERROR} hit exception while querying processor name")
    log.debug("Got proc_name: %s", proc_name)
    if not proc_name:
        print(f"{ERROR} cannot get the processor name. The tool cannot " +
              "determine whether this system could run ECE")
        proc_name = 'unknown'
    elif proc_name == 'x86_64':
        print(f"{INFO} has x86_64 processor which is supported to run ECE")
    elif proc_name == 'aarch64':
        print(f"{INFO} has aarch64 processor which is supported to run ECE")
    else:
        print(f"{ERROR} has {proc_name} processor which is not supported to " +
              "run ECE")
    return proc_name


def check_cpu_by_lscpu(
        is_virt: bool,
        min_socket: int,
        min_cores: int) -> Tuple[bool, int, List]:
    """Use lscpu to check CPU socket and core.
    Args:
        is_virt: is virtual system?
        min_socket: the minimum requirement of socket number.
        min_cores: the minimum requirement of total core number.
    Returns:
        (cpu_error, sock_num, cores)
    """
    errcnt = 0
    if isinstance(is_virt, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter is_virt: {is_virt}")
    if isinstance(min_socket, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_socket: {min_socket}")
    if isinstance(min_cores, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_cores: {min_cores}")
    if errcnt != 0:
        return True, 0, []

    print(f"{INFO} is checking CPU")
    cmd = 'lscpu'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing CPU")
        return True, 0, []
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while listing CPU")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return True, 0, []
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while listing CPU")
        return True, 0, []

    sock_num = 0
    core_per_sock = 0
    model_name = ''
    is_amd = False
    lines = out.strip().splitlines()
    for line in lines:
        line = line.strip()
        if 'Socket(s):' in line:
            try:
                sock_num = int(line.split()[-1])
            except BaseException as e:
                log.debug("Tried to extract socket number from %s but hit "
                          "exception: %s", line, e)
                print(f"{ERROR} hit exception while extracting socket number")
                continue
        if 'Core(s) per socket:' in line:
            try:
                core_per_sock = int(line.split()[-1].strip())
            except BaseException as e:
                log.debug("Tried to extract core number per socket from %s but "
                          "hit exception: %s", line, e)
                print(f"{ERROR} hit exception while extracting core number " +
                      "per socket")
                continue
        if 'Model name' in line and 'BIOS Model name' not in line:
            try:
                model_name = line.split(':')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract Model name from %s but hit "
                          "exception: %s", line, e)
                print(f"{ERROR} hit exception while extracting Model name")
                continue
    log.debug("Got sock_num: %d, core_per_sock: %d, model_name: %s", sock_num,
              core_per_sock, model_name)
    if sock_num < 1:
        print(f"{ERROR} got invalid CPU socket number")
    if core_per_sock < 1:
        print(f"{ERROR} got invalid CPU core number per socket")
    if not model_name:
        print(f"{ERROR} cannot get CPU Model name")
    if sock_num < 1 or core_per_sock < 1 or not model_name:
        return True, 0, []

    cpu_error = False
    # Virtual machine will skip the minimum socket number check
    if is_virt is False:
        if sock_num < min_socket:
            cpu_error = True
            print(f"{ERROR} has {sock_num} CPU socket[s] which is less than " +
                  f"{min_socket} ECE requires")
        elif sock_num <= 2:
            # sock_num >= min_socket and sock_num <= 2
            # Single and dual sockets(Intel or AMD) are supported
            print(f"{INFO} has {sock_num} CPU socket[s] which complies with " +
                  "ECE requirement")
        else:
            # sock_num > 2
            cpu_error = True
            print(f"{ERROR} has {sock_num} CPU sockets which is not verified " +
                  "to support ECE")

    if 'AMD' in model_name:
        is_amd = True
        epyc_gen1_regex = re.compile(r'EPYC\s\d{3}1')
        matched = epyc_gen1_regex.search(model_name)
        if matched:
            print(f"{ERROR} AMD EPYC 1st Generation(Naples) is not supported " +
                  "by ECE")
            return True, 0, []
        print(f"{INFO} has AMD CPU")
    elif 'Intel' in model_name:
        print(f"{INFO} has Intel CPU")
    elif 'aarch64' in model_name:
        print(f"{INFO} has aarch64 CPU")
    else:
        print(f"{ERROR} has {model_name} CPU which is not supported by ECE")
        return True, 0, []

    cores = [core_per_sock]
    cores *= sock_num
    total_core_num = sock_num * core_per_sock
    log.debug("Got sock_num: %d, total_core_num: %s, cores: %s", sock_num,
              total_core_num, cores)

    if is_amd is True and sock_num == 2:
        # dual AMD sockets trigger warning message
        print(f"{WARN} has {sock_num} AMD CPU sockets which may need tuning " +
              "NPS configuration to gain better performance")

    if total_core_num < 1:
        cpu_error = True
        print(f"{ERROR} does not have any CPU core to run ECE")
    elif total_core_num < min_cores:
        print(f"{WARN} has a total of {total_core_num} CPU core[s] which is " +
              f"less than {min_cores} ECE requires")
    else:
        print(f"{INFO} has a total of {total_core_num} CPU cores that " +
              "comply with ECE requirement")

    return cpu_error, sock_num, cores


def check_cpu_by_dmidecode(
        min_socket: int,
        min_cores: int) -> Tuple[bool, int, List]:
    """Use dmidecode to check CPU socket and core.
    Args:
        min_socket: the minimum requirement of socket number.
        min_cores: the minimum requirement of total core number.
    Returns:
        (cpu_error, sock_num, cores)
    """
    errcnt = 0
    if isinstance(min_socket, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_socket: {min_socket}")
    if isinstance(min_cores, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_cores: {min_cores}")
    if errcnt != 0:
        return True, 0, []

    print(f"{INFO} is checking CPU")
    cmd = 'dmidecode --type processor'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran %s. Hit exception: %s", cmd, e)
        print(f"{ERROR} hit exception while querying processor info by " +
              "dmidecode")
        return True, 0, []
    if rc != 0:
        errcnt += 1
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{ERROR} hit error while querying processor info by dmidecode")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return True, 0, []
    if rc == 0 and not out.strip():
        errcnt += 1
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{ERROR} got empty stdout while querying processor info by " +
              "dmidecode")
        return True, 0, []

    handle = ''
    version = ''
    core_cnt = ''
    cpu_kv = {}
    lines = out.strip().splitlines()
    for line in lines:
        line = line.strip()
        if 'Handle' in line and 'DMI type' in line:
            try:
                handle = str(line.split(',')[0].split()[-1])
            except BaseException as e:
                handle = ''
                version = ''
                core_cnt = ''
                log.debug("Tried to extract CPU socket Handle from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting CPU socket " +
                      "Handle")
                continue
            if not handle:
                version = ''
                core_cnt = ''
                log.debug("Tried to extract CPU socket Handle from %s but got "
                          "nothing", line)
                print(f"{WARN} cannot extract CPU socket Handle")
                continue
        if 'Version:' in line:
            try:
                version = line.split(':', 1)[-1].strip()
            except BaseException as e:
                handle = ''
                version = ''
                core_cnt = ''
                log.debug("Tried to extract CPU Version from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting socket Version")
                continue
            if not version:
                handle = ''
                core_cnt = ''
                log.debug("Tried to extract CPU Version from %s but got "
                          "nothing", line)
                print(f"{WARN} cannot extract CPU socket Version")
                continue
        if 'Core Count:' in line:
            try:
                core_cnt = str(line.split(':')[-1].strip())
            except BaseException as e:
                handle = ''
                version = ''
                core_cnt = ''
                log.debug("Tried to extract CPU Core Count from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting CPU Core Count")
                continue
            if not core_cnt:
                handle = ''
                version = ''
                log.debug("Tried to extract CPU Core Count from %s but got "
                          "nothing", line)
                print(f"{WARN} cannot extract CPU Core Count")
                continue
        if handle:
            try:
                _ = cpu_kv[handle]
            except KeyError:
                cpu_kv[handle] = {}
            if version and core_cnt:
                cpu_kv[handle]['version'] = version
                cpu_kv[handle]['core_count'] = core_cnt
    log.debug("Got cpu_kv: %s", cpu_kv)
    if not cpu_kv:
        print(f"{ERROR} cannot get CPU info by dmidecode")
        return True, 0, []

    is_amd = False
    cpu_error = False
    sock_num = 0
    total_core_num = 0
    cores = []
    for key, val in cpu_kv.items():
        ver = ''
        core_cnt = ''
        try:
            ver = val['version']
            core_cnt = val['core_count']
        except KeyError as e:
            log.debug("Tried to extract CPU Version or Core Count from %s but "
                      "hit KeyError: %s", val, e)
            print(f"{WARN} hit exception while extracting CPU Version or " +
                  f"Core Count of socket {key}")
            continue
        if not ver or not core_cnt:
            log.debug("Got ver: %s, core_cnt: %s", ver, core_cnt)
            print(f"{WARN} cannot extract CPU Version or Core Count")
            continue
        if 'AMD' in ver:
            is_amd = True
            epyc_gen1_regex = re.compile(r'EPYC\s\d{3}1')
            matched = epyc_gen1_regex.search(version)
            if matched:
                cpu_error = True
                print(f"{ERROR} has AMD EPYC 1st Generation(Naples) CPU on " +
                      f"socket {key} which is NOT supported by ECE")
            print(f"{INFO} has an AMD CPU socket with handle {key}. It has " +
                  f"{core_cnt} core[s]")
        elif 'Intel' in version:
            print(f"{INFO} has an Intel CPU socket with handle {key}. It " +
                  f"has {core_cnt} core[s]")

        else:
            # ARM processors can have many different vendors, so we do not have a definite
            # way to check if it is supported or not. For now, we assume
            # that any ARM CPU with aarch64 architecture is supported.
            if 'aarch64' in check_processor():
                print(f"{INFO} has an ARM CPU socket with handle {key}. It " +
                      f"has {core_cnt} core[s]")
            else:
                cpu_error = True
                print(f"{ERROR} has {ver} CPU socket with handle {key}. It is " +
                    "NOT supported by ECE")

        sock_num += 1
        core_cnt = int(core_cnt)
        total_core_num += core_cnt
        cores.append(core_cnt)
    log.debug("Got sock_num: %d, total_core_num: %d, cores: %s", sock_num,
              total_core_num, cores)

    if sock_num < min_socket:
        cpu_error = True
        print(f"{ERROR} has {sock_num} CPU socket[s] which is less than " +
              f"{min_socket} ECE requires")
    elif sock_num <= 2:
        # sock_num >= min_socket and sock_num <= 2
        # Single and dual sockets(Intel or AMD) are supported
        print(f"{INFO} has {sock_num} CPU socket[s] which complies with ECE " +
              "requirement")
    else:
        # sock_num > 2
        cpu_error = True
        print(f"{ERROR} has {sock_num} CPU sockets which is not verified to " +
              "support ECE")
    if is_amd is True and cpu_error is False and sock_num == 2:
        # dual AMD sockets trigger warning message
        print(f"{WARN} has {sock_num} AMD CPU sockets which may need tuning " +
              "NPS configuration to gain better performance")
    if total_core_num < 1:
        cpu_error = True
        print(f"{ERROR} does not have any core to run ECE")
    elif total_core_num < min_cores:
        print(f"{WARN} has a total of {total_core_num} CPU core[s] which is " +
              f"less than {min_cores} ECE requires")
    else:
        print(f"{INFO} has a total of {total_core_num} cores that comply " +
              "with ECE requirement")
    return cpu_error, sock_num, cores


def check_os_distribution(supp_os_kv: Dict) -> Tuple[bool, str]:
    """Check OS distribution name.
    Args:
        supp_os_kv: KV pairs from supported_OS.json.
    Returns:
        (os_err, pretty_name)
    """
    if not supp_os_kv or isinstance(supp_os_kv, dict) is False:
        print(f"{ERROR} Invalid parameter supp_os_kv: {supp_os_kv}")
        return True, 'Unknown'

    # Extract supported OS type
    supp_os_types = []
    try:
        raw_types = list(supp_os_kv.keys())
        supp_os_types = [str(i) for i in raw_types if i != 'json_version']
    except BaseException as e:
        log.debug("Tried to extract supported OS types from %s but hit "
                  "exception: %s", supp_os_kv, e)
        print(f"{ERROR} hit exception while extracting supported OS types")
        return True, 'Unknown'

    log.debug("Got supp_os_types: %s", supp_os_types)
    if not supp_os_types:
        print(f"{ERROR} cannot get any supported OS type")
        return True, 'Unknown'

    # RHEL, CentOS, Rocky Linux, SuSE, Ubuntu, Debian has
    # /etc/os-release
    rls_file = '/etc/os-release'
    errcnt = 0
    content = ''
    try:
        with open(rls_file, mode="r", encoding="utf-8") as fh:
            content = fh.read()
    except BaseException as e:
        errcnt += 1
        log.debug("Tried to read %s but hit exception: %s", rls_file, e)
        print(f"{ERROR} hit exception while reading {rls_file}")
    if not content:
        errcnt += 1
        log.debug("Got nothing from %s", rls_file)
        print(f"{ERROR} got nothing from {rls_file}")
    if errcnt != 0:
        return True, 'Unknown'

    pretty_name = ''
    dist_name = ''
    lines = content.strip().splitlines()
    for line in lines:
        if 'PRETTY_NAME' not in line:
            continue
        try:
            pretty_name = line.strip().split('=')[-1].strip('"')
            fields = pretty_name.split()
            dist_name = " ".join(fields[0:-2]).strip()
        except BaseException as e:
            log.debug("Tried to extract OS name but hit exception: %s", e)
            print(f"{ERROR} hit exception while extracting OS name")
    log.debug("Got pretty_name: %s, dist_name: %s", pretty_name, dist_name)
    if not pretty_name:
        print(f"{ERROR} cannot get OS pretty name")
    if not dist_name:
        print(f"{ERROR} cannot get OS distribution name")
    if (not pretty_name) or (not dist_name):
        return True, 'Unknown'

    os_error = False
    if dist_name in supp_os_types:
        supp_stat = ''
        try:
            supp_stat = supp_os_kv[dist_name]
        except KeyError as e:
            log.debug("Tried to extract supporting state of %s from %s but hit "
                      "KeyError: %s", pretty_name, supp_os_kv, e)
            print(f"{ERROR} is running {pretty_name} which is not tested by " +
                  "IBM to run ECE")
            return True, pretty_name

        if not supp_stat:
            os_error = True
            print(f"{ERROR} is running {pretty_name} whose supporting state " +
                  "is not explicitly specified in supported_OS.json")
        elif supp_stat == 'OK':
            print(f"{INFO} is running {pretty_name}")
        elif supp_stat == 'WARN':
            print(f"{WARN} is running {pretty_name}")
        elif supp_stat == 'NOK':
            os_error = True
            print(f"{ERROR} is running {pretty_name} which is NOT OK to run " +
                  "ECE")
        else:
            os_error = True
            print(f"{ERROR} is running {pretty_name} with supporting state: " +
                  f"{supp_stat}")
    else:
        os_error = True
        print(f"{ERROR} is running {pretty_name} which is NOT tested by IBM")

    log.debug("Got os_error: %s, pretty_name: %s", os_error, pretty_name)
    return os_error, pretty_name


def is_pkg_installed(rpm_pkg: str) -> bool:
    """Is input package installed on localhost?
    Args:
        rpm_pkg: keyword of package to be checked.
    Returns:
        0 if package is installed. Else, !0.
    """
    if not rpm_pkg or isinstance(rpm_pkg, str) is False:
        print(f"{ERROR} Invalid parameter rpm_pkg: {rpm_pkg}")
        return 1

    cmd = f"rpm -q {rpm_pkg}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Tried to query: %s but hit exception: %s", rpm_pkg, e)
        print(f"{WARN} hit exception while querying package: {rpm_pkg}")
        return 1
    out = out.strip()
    if out:
        log.debug("Ran: %s. Got stdout: %s", cmd, out)
    if err.strip():
        log.debug("Ran: %s. Got stderr: %s", cmd, err)
    return rc


def check_package(supp_pkg_kv: Dict) -> Tuple[int, Dict]:
    """Check package installation state by input KV pair.
    Args:
        supp_pkg_kv: KV pair in packages.json.
    Returns:
        (errcnt, pkg_ins_kv)
    """
    if not supp_pkg_kv or isinstance(supp_pkg_kv, dict) is False:
        print(f"{ERROR} invalid parameter supp_pkg_kv: {supp_pkg_kv}")
        return 1, {}

    print(f"{INFO} is checking package installation state")
    pkg_errcnt = 0
    pkg_ins_kv = {}
    for key, val in supp_pkg_kv.items():
        key = str(key)
        if key == "json_version":
            continue
        rc = is_pkg_installed(key)
        if rc == 0:
            pkg_ins_kv[key] = 'installed'
            inst_msg = f"has {key} installed"
            if val == 'OK':
                print(f"{INFO} {inst_msg}, which is as expected")
            elif val == 'NOK':
                pkg_errcnt += 1
                print(f"{ERROR} {inst_msg}, which is *NOT* as expected")
        else:
            pkg_ins_kv[key] = 'does_not_install'
            inst_msg = f"does not have {key} installed"
            if val == 'OK':
                pkg_errcnt += 1
                print(f"{ERROR} {inst_msg}, which is *NOT* as expected")
            elif val == 'NOK':
                print(f"{INFO} {inst_msg}, which is as expected")
    log.debug("Got pkg_errcnt: %d, pkg_ins_kv: %s", pkg_errcnt, pkg_ins_kv)
    return pkg_errcnt, pkg_ins_kv


def get_system_serial_number() -> str:
    """Get system serial number.
    Args:
    Returns:
        system serial number.
    """
    ser_num = '00000000'
    print(f"{INFO} is querying system serial number")
    cmd = 'dmidecode -s system-serial-number'
    out, err, rc = runcmd(cmd, True)
    if rc != 0:
        log.debug("Ran %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while getting system serial number")
        if err.strip():
            log.debug("Ran: %s. got error: %s", cmd, err)
    else:
        if not out.strip():
            log.debug("Ran %s. Got empty stdout", cmd)
            print(f"{WARN} got empty system serial number")
        else:
            ser_num = str(out.strip())
    if ser_num == '00000000':
        log.debug("Generated a fake system serial number: %s", ser_num)
        print(f"{WARN} generates a fake system serial number: {ser_num}")
    return ser_num


def check_memory(min_gb_ram: int) -> Dict[str, str]:
    """Check memory.
    Args:
        min_gb_ram: MIN_GB_RAM in HW_requirements.json
    Returns:
        memory KV pair.
    """
    if isinstance(min_gb_ram, int) is False:
        print(f"{ERROR} Invalid parameter min_gb_ram: {min_gb_ram}")
        return {}

    print(f"{INFO} is checking memory")
    cmd = 'dmidecode --type memory'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran %s. Hit exception: %s", cmd, e)
        print(f"{ERROR} hit exception while querying memory info by dmidecode")
        return {}
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{ERROR} hit error while querying memory info by dmidecode")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return {}
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{ERROR} got empty stdout while querying memory info by " +
              "dmidecode")
        return {}

    useful_rows = []
    row_num_after_keyword = 6
    lines = out.strip().splitlines()
    row_cnt = 0
    to_save = False
    for line in lines:
        if 'Handle' in line and 'DMI type' in line and to_save is False:
            useful_rows.append(line.strip())
            row_cnt = 0
            to_save = True
        elif to_save is True and row_cnt < row_num_after_keyword:
            useful_rows.append(line.strip())
            row_cnt += 1
        else:
            to_save = False

    handle = ''
    size = ''
    mem_kv = {}
    for line in useful_rows:
        if 'Handle' in line and 'DMI type' in line:
            try:
                handle = str(line.split(',')[0].split()[-1])
            except BaseException as e:
                handle = ''
                size = ''
                log.debug("Tried to extract memory slot Handle from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting memory slot " +
                      "Handle")
                continue
            if not handle:
                size = ''
                log.debug("Tried to extract memory slot Handle from %s but got "
                          "nothing", line)
                print(f"{WARN} cannot extract memory slot Handle")
                continue
        if 'Physical Memory Array' in line:
            # If line is a sumary, delete this memory handle KV pair.
            try:
                _ = mem_kv[handle]
                del mem_kv[handle]
            except KeyError:
                pass
            handle = ''
            size = ''
            continue
        if 'Size:' in line and \
           'Installed Size:' not in line and \
           'Enabled Size:' not in line:
            if 'No Module Installed' in line:
                log.debug("Memory slot with handle %s does not have any "
                          "module installed", handle)
                size = ''
            else:
                try:
                    # Only set "size" in this condition.
                    size = line.split(':', 1)[-1].strip()
                except BaseException as e:
                    size = ''
                    log.debug("Tried to extract memory Size from %s but hit "
                              "exception: %s", line, e)
                    print(f"{WARN} hit exception while extracting memory Size")
                if not size:
                    log.debug("Memory slot with handle %s does not have the "
                              "'Size' field", handle)
        else:
            # Always set size to '' if No 'Size' was in line.
            size = ''
        if handle:
            try:
                _ = mem_kv[handle]
            except KeyError:
                mem_kv[handle] = {}
            mem_kv[handle]['size'] = size
    log.debug("Got mem_kv: %s", mem_kv)
    if not mem_kv:
        print(f"{ERROR} cannot get memory info by dmidecode")
        return {}

    sizes = []
    for key, val in mem_kv.items():
        size = ''
        try:
            size = val['size']
        except KeyError as e:
            log.debug("Tried to extract memory device Size from %s but hit "
                      "KeyError: %s", val, e)
            print(f"{WARN} hit exception while extracting memory device Size " +
                  f"of slot {key}")
            continue
        if not size:
            continue
        sizes.append(size)
    log.debug("Got memory module sizes: %s", sizes)
    if not sizes:
        print(f"{ERROR} cannot get memory module sizes by dmidecode")
        return {}

    ttl_slot_num = len(mem_kv)
    populated_slot_num = len(sizes)
    vacant_slot_num = ttl_slot_num - populated_slot_num
    if vacant_slot_num == 0:
        print(f"{INFO} has a total of {populated_slot_num} DIMM slot[s] " +
              "which is fully populated")
    else:
        print(f"{WARN} has {populated_slot_num}/{ttl_slot_num}(populated/" +
              "total) DIMM slot[s] which is not optimal if NVMe drive was used")

    mem_err = False
    dedup_sizes = list(set(sizes))
    dedup_size_num = len(dedup_sizes)
    log.debug("Memory modules have %d kinds of size", dedup_size_num)
    if dedup_size_num == 1:
        size_str = " ".join(dedup_sizes)
        print(f"{INFO} Each in-use memory slot is populated with {size_str} " +
              "memory module")
    else:
        mem_err = True
        print(f"{ERROR} has memory modules with different sizes: {dedup_sizes}")

    ttl_mem_size_gib = 0
    try:
        mem_b = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        ttl_mem_size_gib = mem_b / (1024**3)
        ttl_mem_size_gib = round(ttl_mem_size_gib, 2)
    except BaseException as e:
        mem_err = True
        log.debug("Tried to get memory size but hit exception: %s", e)
        print(f"{ERROR} hit exception while calculating memory size")
    log.debug("Required min_gb_ram: %s. Got ttl_mem_size_gib: %s", min_gb_ram,
              ttl_mem_size_gib)

    if not ttl_mem_size_gib or ttl_mem_size_gib <= 0:
        mem_err = True
        print(f"{ERROR} got invalid memory size in GiB")
    else:
        if ttl_mem_size_gib < min_gb_ram:
            mem_err = True
            print(f"{ERROR} has a total of {ttl_mem_size_gib} GiB memory " +
                  f"which is less than {min_gb_ram} GiB ECE requires")
        else:
            print(f"{INFO} has a total of {ttl_mem_size_gib} GiB memory " +
                  "which is sufficient to run ECE")

    mem_kv = {}
    mem_kv['memory_error'] = mem_err
    mem_kv['memory_size'] = ttl_mem_size_gib
    mem_kv['total_dimm_slot_num'] = ttl_slot_num
    mem_kv['populated_dimm_slot_num'] = populated_slot_num
    mem_kv['vacant_dimm_slot_num'] = vacant_slot_num
    mem_kv['dimm_memory_size'] = dedup_sizes

    log.debug("Generated mem_kv: %s", mem_kv)
    return mem_kv


def list_pci_device() -> Dict[str, List]:
    """Run lspci and return a KV pair.
    Args:
    Returns:
        {PciAddress: [deviceType, deviceName],...} if succeeded. Else, {}.
    """
    cmd: str = "lspci"
    out: str = ""
    err: str = ""
    rc: int = 1
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s, hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing PCI device")
        return {}
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        print(f"{ERROR} hit error while listing PCI device")
        return {}
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got emtpy stdout", cmd)
        print(f"{ERROR} got empty stdout while listing PCI device")
        return {}

    lines: List[str] = out.strip().splitlines()
    pci_kv: Dict[str, List] = {}
    for line in lines:
        pci_addr: str = ""
        dev_type: str = ""
        dev_name: str = ""
        try:
            pci_addr = line.split()[0].strip()
            dev_info = line.split(" ", 1)[1].strip()
            dev_info_fields = dev_info.split(":", 1)
            dev_type = dev_info_fields[0].strip()
            dev_name = dev_info_fields[1].strip()
        except BaseException as e:
            log.debug("Tried to extract PCI item from %s but hit exception: %s",
                      line, e)
            print(f"{WARN} hit exception while extracting PCI device item")
            continue
        if not pci_addr or not dev_type or not dev_name:
            log.debug("Got pci_addr: %s, dev_type: %s, dev_name: %s", pci_addr,
                      dev_type, dev_name)
            print(f"{WARN} Got empty PCI address or device type or device name")
            continue
        pci_kv[pci_addr] = [dev_type, dev_name]
    #log.debug("Got pci_kv: %s", pci_kv)
    if not pci_kv:
        log.debug("Got empty pci_kv")
        print(f"{ERROR} got empty PCI device information")
    return pci_kv


def is_nvmecli_installed(ischeck: bool) -> bool:
    """Is nvme-cli installed on localhost.
    Args:
        ischeck: True if check required.
    Returns:
        True if nvme-cli is installed. Else, False.
    """
    if isinstance(ischeck, bool) is False:
        print(f"{WARN} Invalid parameter ischeck: {ischeck}")
        return False
    if ischeck is False:
        # Skip check. Assuming installed.
        log.debug("Assuming 'nvme-cli' is installed")
        return True

    print(f"{INFO} is checking package required by NVMe drive")
    isinstalled = False
    rc = is_pkg_installed('nvme-cli')
    if rc == 0:
        print(f"{INFO} has 'nvme-cli' installed")
        isinstalled = True
    else:
        print(f"{WARN} does not have 'nvme-cli' installed")
        isinstalled = False
    return isinstalled


def get_nvme_idns_kv(devpath: str) -> Dict:
    """Get ID namespace info of NVMe drive.
    Args:
        devpath: /dev/nvmename.
    Returns:
        output of nvme id-ns with json format.
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return {}

    cmd = f"nvme id-ns {devpath} -o json"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while querying id-ns of {devpath}")
        return {}
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while querying id-ns of {devpath}")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return {}
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while querying id-ns of {devpath}")
        return {}

    idns_kv = {}
    try:
        idns_kv = json.loads(out)
    except BaseException as e:
        log.debug("Tried to load output of %s but hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while extracting id-ns of {devpath}")
        return {}

    log.debug("Got idns_kv: %s", idns_kv)
    if not idns_kv:
        print(f"{WARN} cannot extract id-ns of {devpath}")
    return idns_kv


def get_nvme_info() -> Tuple[bool, Dict]:
    """Get information of NVMe drives.
    Args:
    Returns:
        (nvme_err, nvme_kv)
        nvme_err: True if hit error, else, False.
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber], ...} if succeeded. Else, {}.
    """
    print(f"{INFO} is getting information of NVMe drive[s]")
    cmd: str = "nvme list -o json"
    out: str = ""
    err: str = ""
    rc: int = 1
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        nvme_err = True
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing NVMe drive")
        return True, {}
    if rc != 0:
        nvme_err = True
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while listing NVMe drive")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return True, {}
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while listing NVMe drive")
        return False, {}

    devices: List[Dict] = []
    try:
        out_kv = json.loads(out)
        devices = out_kv['Devices']
    except BaseException as e:
        log.debug("Tried to extract Devices from output of %s but hit "
                  "exception: %s", cmd, e)
        print(f"{WARN} hit exception while extracting NVMe drive info")
        return True, {}
    if not devices:
        log.debug("Loaded output of %s, got empty Devices", cmd)
        print(f"{WARN} cannot extract NVMe Devices")
        return True, {}

    nvme_err: bool = False
    nvme_kv: Dict[int, List] = {}
    sizes: List[int] = []
    for index, dev_kv in enumerate(devices):
        psize: int = 0
        devpath: str = ""
        firmwr: str = ""
        modnum: str = ""
        sernum: str = ""
        try:
            if not "DevicePath" in dev_kv: # If no DevicePath, it is a system with no SCSI controllers
                no_scsi_ctrlr = True
                devpath = "/dev/" + dev_kv["Subsystems"][0]["Controllers"][0]["Namespaces"][0]["NameSpace"]
                firmwr = dev_kv["Subsystems"][0]["Controllers"][0]["Firmware"]
                modnum = dev_kv["Subsystems"][0]["Controllers"][0]["ModelNumber"]
                sernum = dev_kv["Subsystems"][0]["Controllers"][0]["SerialNumber"]
                psize = int(dev_kv["Subsystems"][0]["Controllers"][0]["Namespaces"][0]["PhysicalSize"])
            else:
                devpath = dev_kv['DevicePath'].strip()
                firmwr = dev_kv['Firmware']
                modnum = dev_kv['ModelNumber']
                sernum = dev_kv['SerialNumber']
                psize = int(dev_kv['PhysicalSize'])
        except BaseException as e:
            nvme_err = True
            log.debug("Tried to extract NVMe items from %s but hit exception: "
                      "%s", dev_kv, e)
            print(f"{WARN} hit exception while extracting NVMe drive info")
            continue
        if (not psize or psize <= 0) and devpath:
            # Renew psize
            idns_kv = get_nvme_idns_kv(devpath)
            if not idns_kv:
                nvme_err = True
                continue
            try:
                flbas = idns_kv['flbas']
                lbads = int(idns_kv['lbafs'][flbas]['ds'])
                psize = idns_kv['nsze'] * (1 << lbads)
            except BaseException as e:
                nvme_err = True
                log.debug("Tried to extract flbas, lbafs, ds or nsze of %s but "
                          "hit exception: %s", devpath, e)
                print(f"{WARN} hit exception while extracting flbas, lbafs " +
                      f"ds or nsze of {devpath}")
                continue
        log.debug("From index: %s, got DevicePath: %s, ModelNumber: %s, "
                  "PhysicalSize: %s, Firmware: %s, SerialNumber: %s", index,
                  devpath, modnum, psize, firmwr, sernum)
        if devpath and modnum and psize and firmwr and sernum:
            nvme_kv[index] = [devpath, modnum, psize, firmwr, sernum]
            sizes.append(psize)
        else:
            nvme_err = True
            print(f"{WARN} cannot extract all items of NVMe index {index}")
    log.debug("Generated nvme_kv: %s, sizes: %s, nvme_err: %s", nvme_kv, sizes,
              nvme_err)

    if not nvme_kv:
        print(f"{WARN} does not have any proper NVMe drive")
        return nvme_err, {}
    if not sizes:
        print(f"{WARN} cannot get any size of NVMe drive")
        return nvme_err, {}

    unique_sizes = list(set(sizes))
    if len(unique_sizes) == 1:
        print(f"{INFO} all NVMe drives have the same size")
    else:
        print(f"{WARN} not all NVMe drives have the same size")
    return nvme_err, nvme_kv


def get_vwc_by_nvme_getfeature(devpath: str) -> str:
    """Get Volatile Write Cache state of NVMe drives.
    Args:
        devpath: like /dev/nvme0n1.
    Returns:
        'enabled' if Volatile Write Cache enabled.
        'disabled' if Volatile Write Cache did not enable.
        'unknown' if hit error.
    Comments:
        NVMe status: INVALID_FIELD: A reserved coded value or an unsupported
          value in a defined field(0x4002)
        NVMe status: INVALID_FIELD: A reserved coded value or an unsupported
          value in a defined field(0x2002)
        NVMe status: Invalid Field in Command: A reserved coded value or an
          unsupported value in a defined field(0x2)
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return 'unknown'

    cmd = f"nvme get-feature {devpath} -f 6 -s 0"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while getting feature of NVMe {devpath}")
        return 'unknown'
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
            if 'A reserved coded value or an unsupported' in err:
                print(f"{WARN} has {devpath} whose Volatile Write Cache " +
                      "field is unsupported. Please contact the vendor")
            else:
                print(f"{WARN} hit error while getting Volatile Write state " +
                      f"of {devpath}")
        else:
            print(f"{WARN} got error but no info while querying Volatile " +
                  f"Write state of {devpath}")
        return 'unknown'
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} cannot get Volatile Write Cache state of {devpath}")
        return 'unknown'

    lines = out.strip().splitlines()
    vwc_str = ''
    for line in lines:
        line = line.strip()
        # get-feature:0x6 (Volatile Write Cache), Current value:00000000
        # get-feature:0x6 (Volatile Write Cache), Current value:00000001
        if 'Volatile Write Cache' in line and \
           'Current value' in line:
            try:
                vwc_str = str(line[-1])
            except BaseException as e:
                log.debug("Tried to extract VWCE from: %s but hit exception: "
                          "%s", line, e)
                print(f"{WARN} hit exception while extracting Volatile Write " +
                      f"Cache of {devpath}")
                break
        if vwc_str:
            break

    vwc = 'unknown'
    if not vwc_str:
        print(f"{WARN} cannot get any Volatile Write state of {devpath}. " +
              "Marked it as unknown")
        vwc = 'unknown'
    elif vwc_str == '0':
        vwc = 'disabled'
    elif vwc_str == '1':
        vwc = 'enabled'
        print(f"{WARN} has {devpath} with Volatile Write Cache Enabled which " +
              "is not supported to run ECE")

    log.debug("Volatile Write Cache state of %s is %s", devpath, vwc)
    return vwc


def check_nvme_vwc(nvme_kv: Dict[int, List]) -> Tuple[bool, Dict]:
    """Check Volatile Write Cache state of NVMe drives.
    Args:
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber],
                  ...}
    Returns:
        (nvme_wce_err, nvme_kv)
        new nvme_kv may look like,
        {index: [DevicePath, ModelNumber, PhysicalSize, Firmware, SerialNumber,
                 vwc],
         ...}
    """
    if not nvme_kv or isinstance(nvme_kv, dict) is False:
        print(f"{WARN} Invalid parameter nvme_kv: {nvme_kv}")
        return True, {}

    errcnt = 0
    new_nvme_kv = {}
    for key, val in nvme_kv.items():
        new_nvme_attrs = val
        devpath = ''
        try:
            devpath = val[0]
        except IndexError as e:
            errcnt += 1
            # prepare for the worst
            new_nvme_attrs.append(True)
            new_nvme_kv[key] = new_nvme_attrs
            log.debug("Tried to extract NVMe path from %s but hit IndexError: "
                      "%s", val, e)
            print(f"{WARN} hit exception while extracting NVMe path")
            continue
        if not devpath:
            errcnt += 1
            # prepare for the worst
            new_nvme_attrs.append(True)
            new_nvme_kv[key] = new_nvme_attrs
            log.debug("Got empty NVMe path from %s: %s", key, val)
            print(f"{WARN} cannot extract a NVMe path of index {key}")
            continue
        vwc = get_vwc_by_nvme_getfeature(devpath)
        if vwc == 'enabled' or vwc == 'unknown':
            errcnt += 1
            new_nvme_attrs.append(True)
        elif vwc == 'no':
            new_nvme_attrs.append(False)
        new_nvme_kv[key] = new_nvme_attrs

    nvme_wce_err = False
    if errcnt != 0:
        nvme_wce_err = True
    log.debug("Got errcnt: %s, nvme_wce_err: %s, new_nvme_kv: %s", errcnt,
              nvme_wce_err, new_nvme_kv)

    if nvme_wce_err is True:
        print(f"{WARN} All NVMe drives have Volatile Write Cache Enabled " +
              "(VWCE) or unknown VWCE state")
    return nvme_wce_err, new_nvme_kv


def get_nvme_inuse_lbaf(devpath: str) -> str:
    """Get in-use lbaf of NVMe drives.
    Args:
        devpath: /dev/nvmename.
    Returns:
        line of 'in use lbaf' if succeeded. Else, ''.
        E.g., lbaf  1 : ms:0   lbads:12 rp:0 (in use)
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return ''

    cmd = f"nvme id-ns {devpath}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while querying id-ns of {devpath}")
        return ''
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while querying id-ns of {devpath}")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return ''
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got emtpy stdout", cmd)
        print(f"{WARN} got empty stdout while querying id-ns of {devpath}")
        return ''

    inuse_lbafs = []
    lines = out.strip().splitlines()
    for line in lines:
        if 'lbaf' in line and 'in use' in line:
            inuse_lbafs.append(line.strip())

    log.debug("%s has in use lbaf: %s", devpath, inuse_lbafs)
    inuse_lbaf = ''
    if len(inuse_lbafs) == 1:
        inuse_lbaf = inuse_lbafs[0]
    else:
        inuse_lbaf = ''
        print(f"{WARN} {devpath} has invalid in use lbaf")

    return inuse_lbaf


def check_nvme_inuse_lbads(nvme_kv: Dict) -> bool:
    """Check in-use lbad of NVMe drives.
    Args:
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber, vwc],
                  ...}
    Returns:
        True if the checking was passed. Else, False.
    """
    if not nvme_kv or isinstance(nvme_kv, dict) is False:
        print(f"{WARN} Invalid parameter nvme_kv: {nvme_kv}")
        return False

    nvme_num = len(nvme_kv)
    inuse_lbadses = []
    for key, val in nvme_kv.items():
        devpath = ''
        try:
            devpath = val[0]
        except BaseException as e:
            log.debug("Tried to extract NVMe path from %s with index %s but "
                      "hit exception: %s", val, key, e)
            print(f"{WARN} hit exception while extracting NVMe path")
            continue
        if not devpath:
            log.debug("Cannot extract NVMe path from %s with index %s", val,
                      key)
            print(f"{WARN} cannot extract NVMe path")
            continue
        inuse_lbaf = get_nvme_inuse_lbaf(devpath)
        if not inuse_lbaf:
            continue
        inuse_lbads = ''
        try:
            inuse_lbads = str(inuse_lbaf.split()[4].split(':')[-1])
        except BaseException as e:
            log.debug("Tired to extract in use lbads of %s but hit exception: "
                      "%s", devpath, e)
            print(f"{WARN} hit exception while extracting in use lbads of " +
                  f"{devpath}")
        if inuse_lbads:
            inuse_lbadses.append(inuse_lbads)

    log.debug("Got inuse_lbadses: %s", inuse_lbadses)
    if not inuse_lbadses:
        return False
    if len(inuse_lbadses) != nvme_num:
        print(f"{WARN} cannot get all in-use LBA ds of NVMe drives")
        return False
    unique_inuse_lbadses = list(set(inuse_lbadses))
    if len(unique_inuse_lbadses) == 1:
        iu_size = unique_inuse_lbadses[0]
        print(f"{INFO} all NVMe drives have the same in-use LBA ds: {iu_size}")
        return True
    else:
        print(f"{WARN} not all NVMe drives have the same in-use LBA ds")
        return False


def check_nvme_inuse_ms(nvme_kv: Dict) -> bool:
    """Check in-use ms of NVMe dirve.
    Args:
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber, vwc],
                  ...}
    Returns:
        True if the checking was passed. Else, False.
    Comments:
        ms is short for Metadata Size.
    """
    if not nvme_kv or isinstance(nvme_kv, dict) is False:
        print(f"{WARN} Invalid parameter nvme_kv: {nvme_kv}")
        return False

    nvme_num = len(nvme_kv)
    inuse_mses = []
    for key, val in nvme_kv.items():
        devpath = ''
        try:
            devpath = val[0]
        except BaseException as e:
            log.debug("Tried to extract NVMe path from %s with index %s but "
                      "hit exception: %s", val, key, e)
            print(f"{WARN} hit exception while extracting NVMe path")
            continue
        if not devpath:
            log.debug("Cannot extract NVMe path from %s with index %s", val,
                      key)
            print(f"{WARN} cannot extract NVMe path")
            continue
        inuse_lbaf = get_nvme_inuse_lbaf(devpath)
        if not inuse_lbaf:
            continue
        inuse_ms = ''
        try:
            inuse_ms = str(inuse_lbaf.split()[3].split(':')[-1])
        except BaseException as e:
            log.debug("Tired to extract in use ms of %s but hit exception: %s",
                      devpath, e)
            print(f"{WARN} hit exception while extracting in use ms of " +
                  f"{devpath}")
        if inuse_ms:
            inuse_mses.append(inuse_ms)

    log.debug("Got inuse_mses: %s", inuse_mses)
    if not inuse_mses:
        return False
    if len(inuse_mses) != nvme_num:
        print(f"{WARN} cannot get all in-use ms of NVMe drives")
        return False

    unique_inuse_mses = list(set(inuse_mses))
    check_ok = False
    if len(unique_inuse_mses) == 1:
        each_inuse_ms = unique_inuse_mses[0]
        if each_inuse_ms == "0":
            check_ok = True
            print(f"{INFO} all NVMe drives have the same in-use LBA ms: 0")
        else:
            check_ok = False
            print(f"{WARN} all NVMe drives have the same in-use LBA ms: " +
                  f"{each_inuse_ms}")
    else:
        check_ok = False
        print(f"{WARN} not all NVMe drives have the same in-use LBA ms")
    return check_ok


def get_nvme_eui_nguid(nvme_kv: Dict) -> Tuple[bool, Dict]:
    """Get NVMe ID.
    Args:
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber, vwc],
                  ...}
    Returns:
        (id_err, id_kv)
        id_kv likes {devpath: [eui, nguid], ...}.
    """
    if not nvme_kv or isinstance(nvme_kv, dict) is False:
        print(f"{WARN} Invalid parameter nvme_kv: {nvme_kv}")
        return True, {}

    nvme_num = len(nvme_kv)
    id_err = False
    id_kv = {}
    euis = []
    nguids = []
    replica_cnt = 0
    zero_eui = '0000000000000000'
    zero_nguid = '00000000000000000000000000000000'
    for key, val in nvme_kv.items():
        devpath = ''
        try:
            devpath = val[0]
        except BaseException as e:
            id_err = True
            log.debug("Tried to extract NVMe path from %s with index %s but "
                      "hit exception: %s", val, key, e)
            print(f"{WARN} hit exception while extracting NVMe path")
            continue
        if not devpath:
            id_err = True
            log.debug("Cannot extract NVMe path from %s with index %s", val,
                      key)
            print(f"{WARN} cannot extract NVMe path")
            continue
        idns_kv = get_nvme_idns_kv(devpath)
        eui = ''
        nguid = ''
        try:
            eui = str(idns_kv['eui64'])
            nguid = str(idns_kv['nguid'])
        except BaseException as e:
            id_err = True
            log.debug("Tried to extract eui64 or nguid of %s but hit "
                      "exception: %s", devpath, e)
            print(f"{WARN} hit exception while extracting eui64 or nguid of " +
                  f"{devpath}")
            continue
        log.debug("%s has eui64: %s, nguid: %s", devpath, eui, nguid)
        if not eui or not nguid:
            id_err = True
            print(f"{WARN} cannot extract eui64 or nguid of {devpath}")
            continue
        if (eui != zero_eui) and (eui in euis):
            replica_cnt += 1
        if (nguid != zero_nguid) and (nguid in nguids):
            replica_cnt += 1
        euis.append(eui)
        nguids.append(nguid)
        id_kv[devpath] = [eui, nguid]
    log.debug("Got id_err: %s, id_kv: %s", id_err, id_kv)

    if len(id_kv) != nvme_num:
        print(f"{WARN} cannot get all eui64s and nguids of NVMe drives")
        return True, id_kv
    log.debug("Got replica_cnt: %s", replica_cnt)
    if replica_cnt == 0:
        print(f"{INFO} all NVMe drives have their unique IDs")
    else:
        id_err = True
        print(f"{WARN} not all NVMe drives have their unique IDs")

    log.debug("Renewed id_err: %s", id_err)
    return id_err, id_kv


def check_nvme_loghome_size(
        nvme_kv: Dict,
        min_loghome_size: int) -> bool:
    """Check if loghome could be built on NVMe drive.
    Args:
        nvme_kv: {index: [DevicePath, ModelNumber, PhysicalSize, Firmware,
                          SerialNumber, vwc],
                  ...}
        min_loghome_size: MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json.
    Returns:
        True if size of NVMe drive met the requirement. Else, False.
    """
    warncnt = 0
    if not nvme_kv or isinstance(nvme_kv, dict) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter nvme_kv: {nvme_kv}")
    if isinstance(min_loghome_size, int) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter min_loghome_size: {min_loghome_size}")
    if warncnt != 0:
        return False

    size_ok = False
    for key, val in nvme_kv.items():
        int_capacity = 0
        try:
            int_capacity = int(val[2])
        except BaseException as e:
            log.debug("Tried to extract NVMe capacity from %s:%s but hit "
                      "exception: %s", key, val, e)
            print(f"{WARN} hit exception while extracting NVMe capacity of " +
                  f"index: {key}")
            continue
        if not int_capacity:
            log.debug("Size in %s:%s is int_capacity: %s", key, val,
                      int_capacity)
            print(f"{WARN} cannot get NVMe capacity of index: {key}")
            continue
        if int_capacity >= min_loghome_size:
            size_ok = True
            break

    log.debug("Can loghome build on NVMe drive? %s", size_ok)
    return size_ok


def mark_physical_scsi_controller(
        pci_kv: Dict,
        supp_scsi_ctrlr_kv: Dict) -> Dict[str, str]:
    """Mark supporting state of SCSI Controller in physical machine.
    Args:
        pci_kv: output of lspci.
        supp_scsi_ctrlr_kv: SCSI controller supported in SAS_adapters.json.
    Returns:
        pci_marked_ctrlr_kv: {pci1: SCSI_controller1, ...}.
        exit if hit fatal error.
    Comments:
        {'58:00.0': 'Broadcom / LSI MegaRAID Tri-Mode SAS3516 (rev 01) [OK]'}
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_scsi_ctrlr_kv or isinstance(supp_scsi_ctrlr_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_scsi_ctrlr_kv: " +
              f"{supp_scsi_ctrlr_kv}")

    if errcnt != 0:
        return {}

    # Extract supported SCSI controllers
    supp_ctrlrs = []
    try:
        raw_ctrlrs = list(supp_scsi_ctrlr_kv.keys())
        supp_ctrlrs = [str(i) for i in raw_ctrlrs if i != 'json_version']
    except BaseException as e:
        log.debug("Tried to extract supported SCSI controller from: %s but hit "
                  "exception: %s", supp_scsi_ctrlr_kv, e)
        print(f"{ERROR} hit exception while extracting supported SCSI " +
              "controller")
        return {}

    log.debug("Got supp_ctrlrs: %s", supp_ctrlrs)
    if not supp_ctrlrs:
        print(f"{ERROR} cannot get any supported SCSI controller")
        return {}

    print(f"{INFO} is checking SCSI controller")
    # Get alternative SCSI controllers from localhost
    supp_ctrlr_len = len(supp_ctrlrs)
    alt_pci_ctrlr_kv = {}
    for key, val in pci_kv.items():
        pci_addr = key
        dev_type = val[0]
        dev_name = val[1]
        if dev_type != 'SATA controller' and \
           dev_type != 'RAID bus controller' and \
           dev_type != 'Serial Attached SCSI controller':
            continue
        if not pci_addr or not dev_name:
            continue
        alt_pci_ctrlr_kv[pci_addr] = dev_name
    log.debug("Got alt_pci_ctrlr_kv: %s", alt_pci_ctrlr_kv)
    if not alt_pci_ctrlr_kv:
        print(f"{INFO} does not have any PCI address or SCSI controller")
        return {}

    # Marking
    marked_pci_ctrlr_kv = {}
    ok_ctrlrs = []
    notok_ctrlrs = []
    reserved_ctrlrs = []
    nottested_ctrlrs = []
    for key, val in alt_pci_ctrlr_kv.items():
        # split alternative SCSI controller name to word list
        alt_words = val.split()
        if not alt_words:
            continue
        not_match_cnt = 0
        for supp_c in supp_ctrlrs:
            marker = 'Unknown'
            try:
                marker = supp_scsi_ctrlr_kv[supp_c]
            except KeyError as e:
                log.debug("Tried to get marker of %s but hit KeyError: %s",
                          supp_c, e)
                print(f"{WARN} hit exception while extracting marker for " +
                      f"supported SCSI controller: {supp_c}")
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            if not marker:
                marker = 'Unknown'
                log.debug("Got emtpy marker from %s", supp_scsi_ctrlr_kv)
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            # split supported SCSI controller name to word list
            supp_words = supp_c.split()
            if not supp_words:
                continue
            matched = set(supp_words).issubset(set(alt_words))
            if matched is True:
                marked_name = ''
                if marker == 'OK':
                    marked_name = f"{val} [OK]"
                    ok_ctrlrs.append(val)
                elif marker == 'NOK':
                    marked_name = f"{val} [NOT OK]"
                    notok_ctrlrs.append(val)
                else:
                    marked_name = f"{val} [{marker}]"
                    reserved_ctrlrs.append(val)
                if marked_name:
                    marked_pci_ctrlr_kv[key] = marked_name
            else:
                not_match_cnt += 1
        if not_match_cnt == supp_ctrlr_len:
            marked_name = f"{val} [NOT TESTED]"
            marked_pci_ctrlr_kv[key] = marked_name
            nottested_ctrlrs.append(val)
    log.debug("Got marked_pci_ctrlr_kv: %s", marked_pci_ctrlr_kv)

    if not marked_pci_ctrlr_kv:
        print(f"{WARN} cannot mark SCSI controller")
        return {}
    if ok_ctrlrs:
        log.debug("Got ok_ctrlrs: %s", ok_ctrlrs)
        ok_ctrlr_len = len(ok_ctrlrs)
        if ok_ctrlr_len == 1:
            print(f"{INFO} has following SCSI controller tested by IBM")
        else:
            print(f"{INFO} has following SCSI controllers tested by IBM")
        for ok_c in ok_ctrlrs:
            print(f"{INFO} {ok_c}")
        if ok_ctrlr_len == 1:
            print(f"{INFO} disks attached to above SCSI controller can be " +
                  "used by ECE")
        else:
            print(f"{INFO} disks attached to above {ok_ctrlr_len} SCSI " +
                  "controllers can be used by ECE")
    if notok_ctrlrs:
        log.debug("Got notok_ctrlrs: %s", notok_ctrlrs)
        notok_ctrlr_len = len(notok_ctrlrs)
        if notok_ctrlr_len == 1:
            print(f"{ERROR} has following SCSI controller explicitly NOT " +
                  "supported by ECE")
        else:
            print(f"{ERROR} has following SCSI controllers explicitly NOT " +
                  "supported by ECE")
        for notok_c in notok_ctrlrs:
            print(f"{ERROR} {notok_c}")
        if notok_ctrlr_len == 1:
            print(f"{ERROR} disks attached to above SCSI controller cannot " +
                  "be used by ECE")
        else:
            print(f"{ERROR} disks attached to above {notok_ctrlr_len} SCSI " +
                  "controllers cannot be used by ECE")
    if reserved_ctrlrs:
        log.debug("Got reserved_ctrlrs: %s", reserved_ctrlrs)
        rsvd_ctrlr_len = len(reserved_ctrlrs)
        if rsvd_ctrlr_len == 1:
            print(f"{WARN} has following SCSI controller tagged by IBM")
        else:
            print(f"{WARN} has following SCSI controllers tagged by IBM")
        for rsvd_c in reserved_ctrlrs:
            print(f"{WARN} {rsvd_c}")
        if rsvd_ctrlr_len == 1:
            print(f"{WARN} disks attached to above SCSI controller may be " +
                  "used by ECE, depends on the tag")
        else:
            print(f"{WARN} disks attached to above {rsvd_ctrlr_len} SCSI " +
                  "controllers may be used by ECE, depends on the tag")
    if nottested_ctrlrs:
        log.debug("Got nottested_ctrlrs: %s", nottested_ctrlrs)
        ntst_ctrlr_len = len(nottested_ctrlrs)
        if ntst_ctrlr_len == 1:
            print(f"{WARN} has following SCSI controller NOT tested by IBM")
        else:
            print(f"{WARN} has following SCSI controllers NOT tested by IBM")
        for ntst_c in nottested_ctrlrs:
            print(f"{WARN} {ntst_c}")
        if ntst_ctrlr_len == 1:
            print(f"{WARN} disks attached to above SCSI controller may not " +
                  "be used by ECE")
        else:
            print(f"{WARN} disks attached to above {ntst_ctrlr_len} SCSI " +
                  "controllers may not be used by ECE")
    return marked_pci_ctrlr_kv


def mark_vmware_scsi_controller(
        pci_kv: Dict,
        supp_scsi_ctrlr_kv: Dict) -> Dict[str, str]:
    """Mark supporting state of SCSI Controller in VMware machine.
    Args:
        pci_kv: output of lspci.
        supp_scsi_ctrlr_kv: SCSI controller supported in SAS_adapters.json.
    Returns:
        {'PCI address': 'SCSI controller', ...} if succeeded. Elese, {}.
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_scsi_ctrlr_kv or isinstance(supp_scsi_ctrlr_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_scsi_ctrlr_kv: " +
              f"{supp_scsi_ctrlr_kv}")
    if errcnt != 0:
        return {}

    # Extract supported SCSI controllers
    supp_ctrlrs = []
    try:
        raw_ctrlrs = list(supp_scsi_ctrlr_kv.keys())
        supp_ctrlrs = [i for i in raw_ctrlrs if i != 'json_version']
    except BaseException as e:
        log.debug("Tried to extract supported SCSI controller from: %s But hit "
                  "exception: %s", supp_scsi_ctrlr_kv, e)
        print(f"{WARN} hit exception while extracting supported SCSI " +
              "controller")
        return {}
    log.debug("Got supp_ctrlrs: %s", supp_ctrlrs)
    if not supp_ctrlrs:
        print(f"{WARN} got empty supported SCSI controller")
        return {}

    print(f"{INFO} is checking SCSI controller")
    # Get local SCSI controllers as alternative SCSI controllers
    supp_ctrlr_len = len(supp_ctrlrs)
    alt_pci_ctrlr_kv = {}
    for key, val in pci_kv.items():
        pci_addr = key
        dev_type = val[0]
        dev_name = val[1]
        if dev_type != 'SATA controller' and \
           dev_type != 'RAID bus controller' and \
           dev_type != 'SCSI storage controller' and \
           dev_type != 'Serial Attached SCSI controller':
            continue
        if not pci_addr or not dev_name:
            continue
        alt_pci_ctrlr_kv[pci_addr] = dev_name
    log.debug("Got alt_pci_ctrlr_kv: %s", alt_pci_ctrlr_kv)
    if not alt_pci_ctrlr_kv:
        print(f"{INFO} does not have any PCI address or SCSI controller")
        return {}

    # Marking
    marked_pci_ctrlr_kv = {}
    ok_ctrlrs = []
    notok_ctrlrs = []
    reserved_ctrlrs = []
    nottested_ctrlrs = []
    for key, val in alt_pci_ctrlr_kv.items():
        # split alternative SCSI controller name to word list
        alt_words = val.split()
        if (not alt_words) or (not key):
            continue
        not_match_cnt = 0
        for supp_c in supp_ctrlrs:
            marker = 'Unknown'
            try:
                marker = supp_scsi_ctrlr_kv[supp_c]
            except KeyError as e:
                log.debug("Tried to get marker of %s but hit KeyError: %s",
                          supp_c, e)
                print(f"{WARN} hit exception while extracting marker for " +
                      f"supported SCSI controller: {supp_c}")
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            if not marker:
                marker = 'Unknown'
                log.debug("Got emtpy marker from %s", supp_scsi_ctrlr_kv)
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            # split supported SCSI controller name to word list
            supp_words = supp_c.split()
            if not supp_words:
                continue
            matched = set(supp_words).issubset(set(alt_words))
            if matched is True:
                marked_name = ''
                if marker == 'OK':
                    marked_name = f"{val} [OK]"
                    ok_ctrlrs.append(val)
                elif marker == 'NOK':
                    marked_name = f"{val} [NOT OK]"
                    notok_ctrlrs.append(marked_name)
                else:
                    marked_name = f"{val} [{marker}]"
                    reserved_ctrlrs.append(marked_name)
                if marked_name:
                    marked_pci_ctrlr_kv[key] = marked_name
            else:
                not_match_cnt += 1
        if not_match_cnt == supp_ctrlr_len:
            marked_name = f"{val} [NOT TESTED]"
            marked_pci_ctrlr_kv[key] = marked_name
            nottested_ctrlrs.append(val)

    log.debug("Got marked_pci_ctrlr_kv: %s", marked_pci_ctrlr_kv)
    if not marked_pci_ctrlr_kv:
        print(f"{WARN} cannot mark SCSI controller")
        return {}

    need_to_run_stortool = False
    if ok_ctrlrs:
        log.debug("Got ok_ctrlrs: %s", ok_ctrlrs)
        ok_ctrlr_len = len(ok_ctrlrs)
        if ok_ctrlr_len == 1:
            print(f"{INFO} has following SCSI controller tested by IBM")
        else:
            print(f"{INFO} has following SCSI controllers tested by IBM")
        for ok_c in ok_ctrlrs:
            print(f"{INFO} {ok_c}")
        if ok_ctrlr_len == 1:
            print(f"{INFO} disks attached to above SCSI controller can be " +
                  "used by ECE")
        else:
            print(f"{INFO} disks attached to above {ok_ctrlr_len} SCSI " +
                  "controllers can be used by ECE")
    if notok_ctrlrs:
        log.debug("Got notok_ctrlrs: %s", notok_ctrlrs)
        notok_ctrlr_len = len(notok_ctrlrs)
        if notok_ctrlr_len == 1:
            print(f"{ERROR} has following SCSI controller explicitly NOT " +
                  "supported by ECE")
        else:
            print(f"{ERROR} has following SCSI controllers explicitly NOT " +
                  "supported by ECE")
        for notok_c in notok_ctrlrs:
            print(f"{ERROR} {notok_c}")
        if notok_ctrlr_len == 1:
            print(f"{ERROR} disks attached to above SCSI controller cannot " +
                  "be used by ECE")
        else:
            print(f"{ERROR} disks attached to above {notok_ctrlr_len} SCSI " +
                  "controllers cannot be used by ECE")
    if reserved_ctrlrs:
        need_to_run_stortool = True
        log.debug("Got reserved_ctrlrs: %s", reserved_ctrlrs)
        rsvd_ctrlr_len = len(reserved_ctrlrs)
        if rsvd_ctrlr_len == 1:
            print(f"{WARN} has following SCSI controller tagged by IBM")
        else:
            print(f"{WARN} has following SCSI controllers tagged by IBM")
        for rsvd_c in reserved_ctrlrs:
            print(f"{WARN} {rsvd_c}")
        if rsvd_ctrlr_len == 1:
            print(f"{WARN} disks attached to above SCSI controller may be " +
                  "used by ECE, depends on the tag")
        else:
            print(f"{WARN} disks attached to above {rsvd_ctrlr_len} SCSI " +
                  "controllers may be used by ECE, depends on the tag")
    if nottested_ctrlrs:
        need_to_run_stortool = True
        log.debug("Got nottested_ctrlrs: %s", nottested_ctrlrs)
        ntst_ctrlr_len = len(nottested_ctrlrs)
        if ntst_ctrlr_len == 1:
            print(f"{WARN} has following SCSI controller NOT tested by IBM")
        else:
            print(f"{WARN} has following SCSI controllers NOT tested by IBM")
        for ntst_c in nottested_ctrlrs:
            print(f"{WARN} {ntst_c}")
        if ntst_ctrlr_len == 1:
            print(f"{WARN} disks attached to above SCSI controller may not " +
                  "be used by ECE")
        else:
            print(f"{WARN} disks attached to above {ntst_ctrlr_len} SCSI " +
                  "controllers may not be used by ECE")

    if need_to_run_stortool is True:
        print(f"{INFO} needs to run {STOR_TOOL}")

    return marked_pci_ctrlr_kv


def get_nvme_drive_num() -> int:
    """Get number of NVMe drive.
    Args:
    Returns:
        Number of NVMe drive if succeeded. Else, -1.
    """
    nvmes = []
    nvme_dir = '/sys/class/nvme'
    print(f"{INFO} is checking NVMe drive")
    if os.path.exists(nvme_dir) is False:
        print(f"{WARN} does not have any NVMe drive")
        return 0

    try:
        nvmes = os.listdir(nvme_dir)
    except BaseException as e:
        log.debug("Tried to list %s but hit exception: %s", nvme_dir, e)
        print(f"{WARN} hit exception while listing {nvme_dir}")
        return -1

    nvme_num = len(nvmes)
    log.debug("Got nvme_num: %s from %s", nvme_num, nvme_dir)

    if nvme_num == 0:
        print(f"{WARN} does not have any NVMe drive")
    elif nvme_num == 1:
        print(f"{INFO} has a total of {nvme_num} NVMe drive")
    else:
        print(f"{INFO} has a total of {nvme_num} NVMe drives")

    return nvme_num


def get_controller_number_by_megaraid_tool() -> int:
    """Got Number of Controllers managed by the MegaRAID tool.
    Args:
    Returns:
        Number of Controllers managed by the MegaRAID tool if succeeded.
        Else, -1.
    """
    cmd = f"{MSM_APP} show"
    out, err, rc = runcmd(cmd, True)
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while showing info with MegaRAID tool")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return -1
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while showing info with MegaRAID tool")
        return -1

    lines = out.strip().splitlines()
    ctrlr_num = 0
    for line in lines:
        if 'Number of Controllers =' in line:
            line = line.strip()
            try:
                ctrlr_num = int(line.split('=')[-1].strip())
                break
            except BaseException as e:
                log.debug("Tried to extract SCSI controller number from %s but "
                          "hit exception: %s", line, e)
                print(f"{WARN} hit exception while extracting SCSI " +
                      "controller number by the MegaRAID tool")
                return -1

    log.debug("MegaRAID tool got ctrlr_num: %d", ctrlr_num)
    if ctrlr_num == 0:
        print(f"{WARN} cannot get Controller managed by the MegaRAID tool")
    elif ctrlr_num == 1:
        print(f"{INFO} has 1 Controller managed by the MegaRAID tool")
    else:
        print(f"{INFO} has {ctrlr_num} Controllers managed by the MegaRAID " +
              "tool")
    return ctrlr_num


def get_scsi_controller_interface_types() -> List[str]:
    """Get Device Interface type by MegaRAID the tool.
    Args:
    Returns:
        Controller interface types if succeeded. Else, [].
    Comments:
        E.g., Device Interface = SAS-12G
    """
    cmd = f"{MSM_APP} /call show all"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while showing all MegaRAID info")
        return []
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while showing all MegaRAID info")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return []
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while showing all MegaRAID info")
        return []
    lines = out.strip().splitlines()
    if_types = []
    for line in lines:
        line = line.strip()
        if 'Device Interface =' not in line:
            continue
        if_type = ''
        try:
            fields = line.split('=')
            if_type = fields[-1].strip()
        except BaseException as e:
            log.debug("Tried to extract device interface type from %s but hit "
                      "exception: %s", line, e)
            print(f"{WARN} hit exception while extracting Device Interface " +
                  "type")
        if if_type:
            if_types.append(if_type)
    log.debug("Got if_types: %s", if_types)

    if not if_types:
        print(f"{WARN} cannot get any Device Interface type")
    return if_types


def map_storage_pci_to_logicalname() -> Dict[str, str]:
    """Map storage PCI-E address to logical name.
    Args:
    Returns:
        {pciAddress: logicalName, ...} if succeeded. Else, {}.
        E.g., {'0000:58:00.0': 'scsi0', ...}.
    """
    cmd = 'lshw -class storage -quiet'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing storage hardware")
        return {}
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while listing storage hardware")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return {}
    if rc == 0 and not out.strip():
        print(f"{WARN} got empty stdout while listing storage hardware")
        return {}

    lines = out.strip().splitlines()
    pci_lgnm_kv = {}
    pci_addr = ''
    lgc_name = ''
    for line in lines:
        line = line.strip()
        if 'bus info:' in line and 'pci@' in line:
            try:
                pci_addr = line.split('pci@')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract SCSI controller PCI address from " +
                          "%s but hit exception: %s", line, e)
                print(f"{WARN} hit exception while extracting SCSI " +
                      "controller PCI address")
        if not pci_addr:
            continue
        if 'logical name:' in line and 'nvme' not in line:
            try:
                lgc_name = line.split('logical name:')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract SCSI controller logical name from "
                          "%s but hit exception: %s", line, e)
                print(f"{WARN} hit exception while extracting SCSI " +
                      "controller logical name")
        if pci_addr and lgc_name:
            pci_lgnm_kv[pci_addr] = lgc_name

    log.debug("Got pci_lgnm_kv: %s", pci_lgnm_kv)
    return pci_lgnm_kv


def map_hctl_to_disktype() -> Dict[str, str]:
    """Map H:T:C:L to disk type.
    Args:
    Returns:
        {htcl: diskType, ...} if succeeded. Else, {}.
    """
    cmd = 'lshw -class disk -quiet'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing hardware of disk")
        return {}
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while listing hardware of disk")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return {}
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got emtpy stdout", cmd)
        print(f"{WARN} got empty stdout while listing hardware of disk")
        return {}

    lines = out.strip().splitlines()
    reversed_lines = list(reversed(lines))
    hctl_dtype_kv = {}
    colon_hctl = ''
    disk_type = ''
    for line in reversed_lines:
        line = line.strip()
        if 'bus info:' in line and 'scsi@' in line:
            try:
                raw_hctl = line.split('scsi@')[-1].strip()
                colon_hctl = raw_hctl.replace('.', ':')
            except BaseException as e:
                log.debug("Tried to extract H:C:T:L from %s but hit exception: "
                          "%s", line, e)
                print(f"{WARN} hit exception while disk extracting H:C:T:L")
                continue
            if not colon_hctl:
                log.debug("Cannot extract colon_hctl from %s", line)
                continue
        if 'description:' in line and 'NVMe disk' not in line:
            try:
                disk_type = line.split(':')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract description from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting disk description")
                continue
            if not disk_type:
                log.debug("Cannot extract disk_type from %s", line)
                continue
        if colon_hctl and disk_type:
            hctl_dtype_kv[colon_hctl] = disk_type
    log.debug("Got hctl_dtype_kv: %s", hctl_dtype_kv)

    return hctl_dtype_kv


def get_supported_ctrlr_logicalname(scsi_ctrlr_kv: Dict) -> List[str]:
    """Get logical names of supported SCSI controllers.
    Args:
        scsi_ctrlr_kv: {pciAddress: SCSIController, ...}
    Returns:
        [scsi0, scsi1, ...] if succeeded. Else, [].
    """
    if not scsi_ctrlr_kv or isinstance(scsi_ctrlr_kv, dict) is False:
        print(f"{WARN} Invalid parameter scsi_ctrlr_kv: {scsi_ctrlr_kv}")
        return []

    pci_lgcnm_kv = map_storage_pci_to_logicalname()
    # pci_lgcnm_kv likes: {'0000:58:00.0': 'scsi0'}
    if not pci_lgcnm_kv:
        return []

    supp_ctrlr_lgcnms = []
    for key, val in scsi_ctrlr_kv.items():
        log.debug("Original PCI address is %s", key)
        # Re-set colon_split_scsi_len to 0 for each iteration
        colon_split_scsi_len = 0
        try:
            colon_split_scsi_len = len(key.split(':'))
        except BaseException as e:
            log.debug("Tried to get length of colon split PCI addr %s but hit "
                      "exception: %s", key, e)
            print(f"{WARN} hit exception while getting length of colon split " +
                  "PCI address")
            continue
        if colon_split_scsi_len < 2 or colon_split_scsi_len > 3:
            log.debug("Invalid PCI address: %s", key)
            print(f"{WARN} got invalid PCI address {key}")
            continue
        scsi_addr = key
        if colon_split_scsi_len == 2:
            # Update SCSI address to standard format: filling 0
            scsi_addr = f"0000:{key}"
        ctrlr_lgcnm = ''
        try:
            ctrlr_lgcnm = pci_lgcnm_kv[scsi_addr]
        except KeyError as e:
            log.debug("Tried to extract SCSI ID but hit KeyError %s", e)
            print(f"{INFO} cannot get SCSI logical name of {val}")
            continue
        if not ctrlr_lgcnm:
            log.debug("Got empty SCSI ID of %s", val)
            continue
        supp_ctrlr_lgcnms.append(ctrlr_lgcnm)
    log.debug("Got supp_ctrlr_lgcnms: %s", supp_ctrlr_lgcnms)

    return supp_ctrlr_lgcnms


def list_block_device() -> List[Dict[str, str]]:
    """Run lsblk and do simple pretreatment.
    Args:
    Returns:
        json format output of lsblk if succeeded. Else, {}.
    """
    options = 'hctl,size,log-sec,model,wwn,kname,fstype,mountpoint,rota,state'
    #cmd = f"lsblk --path --output {options} --pairs"
    cmd = f"lsblk -iJpo {options}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing block device")
        return []
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while listing block device")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        # stdout is unreliable
        return []
    if not out.strip():
        log.debug("Ran: %s. Got emtpy stdout", cmd)
        print(f"{WARN} got empty stdout while listing block device")
        return []

    blockdevices = []
    try:
        blk_kv = json.loads(out.strip())
        blockdevices = blk_kv['blockdevices']
    except BaseException as e:
        log.debug("Tried to extract blockdevices from output of lsblk but "
                  "hit exception: %s", e)
        print(f"{WARN} hit exception while extract blockdevices")
        return []
    if not blockdevices:
        log.debug("lsblk but got no blockdevice")
        print(f"{WARN} got no block device by lslbk")
        return []

    return blockdevices


def get_os_disk(blkdevs: List) -> List[str]:
    """Get disks that OS installed.
    Args:
        blkdevs: got from lsblk.
    Returns:
        a list of disks on which OS is installed if succeeded. Else, [].
    """
    if not blkdevs or isinstance(blkdevs, list) is False:
        print(f"{WARN} Invalid parameter blkdevs: {blkdevs}")
        return []

    os_disks = []
    for bdev in blkdevs:
        kname = ''
        try:
            raw_kname = bdev['kname'].strip()
            kname = "".join([i for i in raw_kname if not i.isdigit()])
        except BaseException as e:
            log.debug("Tried to extract kname from %s but hit exception: %s",
                      bdev, e)
            print(f"{WARN} hit exception while extracting kname")
            continue
        if not kname:
            log.debug("Got empty kname from %s", bdev)
            print(f"{WARN} cannot get kname of block device")
            continue
        mountpoint = ''
        try:
            mountpoint = bdev['mountpoint']
        except BaseException as e:
            log.debug("Tried to extract mountpoint from %s but hit exception: "
                      "%s", bdev, e)
            print(f"{WARN} hit exception while extracting mountpoint")
            continue
        if not mountpoint or mountpoint is None:
            continue
        if '/boot' in mountpoint:
            # Got disk on which OS was installed
            os_disks.append(kname)

    os_disks = list(set(os_disks))
    log.debug("Got os_disks: %s", os_disks)
    return os_disks


def get_wce_by_sginfo(devpath: str) -> str:
    """Use sginfo command to get Write Cache Enable state of SG device.
    Args:
        devpath: like /dev/sda.
    Returns:
        'yes' if Write Cache enabled.
        'no' if Write Cache did not enable.
        'unknown' if hit error.
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return 'unknown'

    cmd: str = f"/usr/bin/sginfo -c {devpath}"
    out: str = ""
    err: str = ""
    rc: int = 1
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while extracting write cache of SG " +
              f"device {devpath} by command {cmd}")
        return 'unknown'
    log.debug("Ran: %s. Got return code: %d", cmd, rc)

    if rc != 0:
        if out.strip():
            log.debug("Got stdout:\n%s", out)
        if err.strip():
            log.debug("Got stderr:\n%s", err)

        cmd = f"/usr/bin/sginfo -6 -c {devpath}"
        log.debug("Added option '-6' and ran: %s", cmd)
        try:
            # Renew out, err and rc.
            out, err, rc = runcmd(cmd)
        except BaseException as e:
            log.debug("Ran: %s. Hit exception: %s", cmd, e)
            print(f"{WARN} hit exception while extracting write cache of SG " +
                  f"device {devpath} by command {cmd}")
            return 'unknown'
        log.debug("Ran: %s. Got return code: %d", cmd, rc)

    if rc != 0:
        if out.strip():
            log.debug("Got stdout:\n%s", out)
        if err.strip():
            log.debug("Got stderr:\n%s", err)
            if 'no corresponding SG device found' in err:
                print(f"{WARN} {devpath} is not an SG device. Cannot get " +
                      "its write cache state")
            else:
                # Check debug log.
                print(f"{WARN} hit error while extracting write cache of " +
                      f"{devpath}")
        return 'unknown'

    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} cannot get write cache of SG device {devpath}")
        return 'unknown'

    lines: List[str] = out.strip().splitlines()
    wce_str: str = ""
    for line in lines:
        line = line.strip()
        if 'Write Cache Enabled' in line:
            try:
                wce_str = str(line.split()[-1].strip())
            except BaseException as e:
                log.debug("Tried to extract SG WCE from %s but hit exception: "
                          "%s", line, e)
            break
    log.debug("Got wce_str: %s", wce_str)

    sg_wce: str = "unknown"
    if not wce_str:
        sg_wce = 'unknown'
        print(f"{WARN} cannot get SG Write Cache state of {devpath}. Marked " +
              "it as unknown")
    elif wce_str == '0':
        sg_wce = 'no'
        log.debug("%s has SG Write Cache Disabled", devpath)
    elif wce_str == '1':
        sg_wce = 'yes'
        log.debug("%s has SG Write Cache Enabled", devpath)
        print(f"{WARN} has {devpath} with SG Write Cache Enabled which is " +
              "not supported by ECE")
    else:
        sg_wce = 'unknown'
        print(f"{WARN} has {devpath} whose SG Write Cache state has an " +
              f"unknown value: {wce_str}")
    log.debug("%s has SG Write Cache Enabled state: %s", devpath, sg_wce)
    return sg_wce


def check_write_cache_of_scsi_dev(dev_kv: Dict) -> Tuple[bool, Dict]:
    """Check Write Cache state of SCSI device. Update the dev_kv.
    Args:
        dev_kv: {hctl: [size_val, size_unit, logsec, model, wwn, mapping_state,
                        kname],
                 ...}
    Returns:
        (is_wc_ok, dev_kv)
        new dev_kv may look like,
        {hctl: [size_val, size_unit, logsec, model, wwn, mapping_state, kname,
                sginfo_WCE, megaraid_WCE],
         ...}
    """
    if not dev_kv or isinstance(dev_kv, dict) is False:
        print(f"{WARN} Invalid parameter dev_kv: {dev_kv}")
        return False, {}

    wc_disabled_devs = []
    wc_enabled_devs = []
    wc_unknown_devs = []
    # Directly set WCE gotten from MegaRAID tool
    megaraid_wce = 'MegaRAID_Write_Cache_unknown'
    sg_unkn_str = 'sginfo_Write_Cache_unknown'
    sg_en_str = 'sginfo_Write_Cache_Enabled'
    sg_dis_str = 'sginfo_Write_Cache_Disabled'
    new_dev_kv = {}
    for key, val in dev_kv.items():
        new_val = val
        devpath = ''
        try:
            devpath = val[6]
        except IndexError as e:
            new_val.append(sg_unkn_str)
            new_val.append(megaraid_wce)
            log.debug("Tried to extract disk path from %s but hit IndexError: "
                      "%s", val, e)
            print(f"{WARN} hit exception while extracting disk path of {key}")
            continue
        if not devpath:
            new_val.append(sg_unkn_str)
            new_val.append(megaraid_wce)
            log.debug("Got empty disk path from %s %s", key, val)
            print(f"{WARN} cannot extract the disk path of {key}")
            continue
        wce = get_wce_by_sginfo(devpath)
        if wce == 'yes':
            wc_enabled_devs.append(devpath)
            new_val.append(sg_en_str)
        elif wce == 'no':
            wc_disabled_devs.append(devpath)
            new_val.append(sg_dis_str)
        elif wce == 'unknown':
            wc_unknown_devs.append(devpath)
            new_val.append(sg_unkn_str)
        new_val.append(megaraid_wce)
        new_dev_kv[key] = new_val
    log.debug("Updated dev_kv: %s", dev_kv)
    log.debug("To new_dev_kv: %s", new_dev_kv)

    wc_ok = False
    if wc_enabled_devs or wc_unknown_devs:
        wc_ok = False
    else:
        wc_ok = True
    log.debug("Is all write cache OK? %s", wc_ok)

    if wc_disabled_devs:
        wcd_dev_str = ", ".join(wc_disabled_devs)
        print(f"{INFO} has {wcd_dev_str} with Write Cache Disabled")
    if wc_enabled_devs:
        wce_dev_str = ", ".join(wc_enabled_devs)
        print(f"{WARN} has {wce_dev_str} with Write Cache Enabled")
    if wc_unknown_devs:
        wcu_dev_str = ", ".join(wc_unknown_devs)
        print(f"{WARN} has {wcu_dev_str} with Write Cache Unknown")
    return wc_ok, new_dev_kv


def check_sata_dpofua(devpath: str) -> bool:
    """Check DpoFua setting of SATA device.
    Args:
        devpath: like /dev/sda.
    Returns:
        True if DpoFua value is OK. Else, False.
    Comments:
        DpoFua(Disabed page out, Force unit access) should be set to 1
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return False

    cmd = f"/bin/sg_modes {devpath}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Tried to query SG modes of %s but hit exception: %s",
                  devpath, e)
        print(f"{WARN} hit exception while querying SG modes of {devpath}")
        return False
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while querying SG modes of {devpath}")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return False
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while querying SG modes of {devpath}")
        return False

    # DpoFua line may look like:
    # Mode data length=44, medium type=0x00, WP=0, DpoFua=0, longlba=0
    lines = out.strip().splitlines()
    dpofua_val = ''
    for line in lines:
        line = line.strip()
        if 'DpoFua' in line:
            try:
                nospace_str = line.replace(' ', '')
                dpofua_str = nospace_str.split(',')[3]
                dpofua_val = str(dpofua_str.split('=')[-1])
            except BaseException as e:
                log.debug("Tried to extract DpoFua setting from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting DpoFua setting " +
                      f"of {devpath}")
            break
    log.debug("Got DpoFua setting: %s", dpofua_val)

    dpofua_ok = False
    if not dpofua_val:
        dpofua_ok = False
        print(f"{WARN} cannot extract DpoFua setting of {devpath}")
    elif dpofua_val == "1":
        dpofua_ok = True
        print(f"{INFO} has SATA device {devpath} whose DpoFua setting is " +
              f"{dpofua_val}")
    else:
        dpofua_ok = False
        print(f"{WARN} has SATA device {devpath} whose DpoFua setting is " +
              f"{dpofua_val}. But it should be set to 1")

    log.debug("Is %s DpoFua setting OK? %s", devpath, dpofua_val)
    return dpofua_ok


def check_sata_scterc(devpath: str) -> bool:
    """Check scterc[READTIME,WRITETIME] of SATA device.
    Args:
        devpath: like /dev/sda.
    Returns:
        True if SCT Error Recovery Control is OK. Else, False.
    Comments:
        Smart Command Transport (SCT)
        Error Recovery Control (ERC)
        scterc[,READTIME,WRITETIME]
        For RAID configurations, this is typically set to 70,70 deciseconds
        Read/Write time should be <= 100 deciseconds
    """
    if not devpath or isinstance(devpath, str) is False:
        print(f"{WARN} Invalid parameter devpath: {devpath}")
        return False

    # Self-Monitoring, Analysis and Reporting Technology (SMART)
    cmd = f"/sbin/smartctl -l scterc {devpath}"
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Tried to query scterc[READTIME,WRITETIME] of %s but hit "
                  "exception: %s", devpath, e)
        print(f"{WARN} hit exception while querying scterc[READTIME,WRITETIME" +
              f"] of {devpath}")
        return False

    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while querying scterc[READTIME,WRITETIME] " +
              f"of {devpath}")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return False
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty stdout while querying scterc[READTIME," +
              f"WRITETIME] of {devpath}")
        return False

    # lines may look like:
    #  Read: 70 (7.0 seconds)
    #  Write: 70 (7.0 seconds)
    # or
    # Read: Disabled
    # Write: Disabled
    lines = out.strip().splitlines()
    readtime = 0
    writetime = 0
    for line in lines:
        line = line.strip()
        if 'Read' in line:
            if 'Disabled' in line:
                log.debug("scterc READTIME setting of %s is Disabled", devpath)
                print(f"{WARN} has {devpath} whose scterc READTIME setting " +
                      "is Disabed")
                continue
            try:
                readtime = int(line.split()[1].strip())
            except BaseException as e:
                log.debug("Tried to extract scterc READTIME setting of %s but "
                          "hit exception: %s", devpath, e)
                print(f"{WARN} hit exception while extracting scterc " +
                      f"READTIME setting of {devpath}")
                continue
        elif 'Write' in line:
            if 'Disabled' in line:
                log.debug("scterc WRITETIME setting of %s is Disabled", devpath)
                print(f"{WARN} has {devpath} whose scterc WRITETIME setting " +
                      "is Disabed")
                continue
            try:
                writetime = int(line.split()[1].strip())
            except BaseException as e:
                log.debug("Tried to extract scterc WRITETIME setting of %s but "
                          "hit exception: %s", devpath, e)
                print(f"{WARN} hit exception while extracting scterc " +
                      f"WRITETIME setting of {devpath}")
                continue
    log.debug("Got scterc READTIME: %s, WRITETIME: %s", readtime, writetime)

    scterc_ok = False
    max_time = max(readtime, writetime)
    if max_time > 0 and max_time <= 100:
        scterc_ok = True
        print(f"{INFO} has SATA device {devpath} whose scterc READTIME and " +
              "WRITETIME settings are OK")
    else:
        scterc_ok = False
        print(f"{WARN} has SATA device {devpath} whose scterc READTIME or " +
              "WRITETIME setting is not OK")

    log.debug("Are %s scterc READTIME and WRITETIME settings OK? %s", devpath,
              scterc_ok)
    return scterc_ok


def check_sata_device(sata_devs: List) -> bool:
    """Check SATA device.
    Args:
        sata_devs: SATA device list.
    Returns:
        True if all SATA devices passed the check. Else, False.
    """
    if not sata_devs or isinstance(sata_devs, list) is False:
        print(f"{WARN} Invalid parameters sata_devs: {sata_devs}")
        return False

    errcnt = 0
    for dev in sata_devs:
        dpofua_rc = check_sata_dpofua(dev)
        if dpofua_rc is False:
            errcnt += 1
        scterc_rc = check_sata_scterc(dev)
        if scterc_rc is False:
            errcnt += 1
    return errcnt == 0


def get_available_block_device(
        ok_scsi_ctrlr_kv: Dict,
        os_devs: List,
        check_sata: bool=False) -> Dict[str, Dict]:
    """Get available block device.
    Args:
        ok_scsi_ctrlr_kv: {pciAddress: scsiController, ...}.
        os_devs: a list of disk on which OS is installed.
        check_sata: enable SATA device check. Default is False.
    Returns:
        {'SAS_HDD': {
                     'write_cache_ok': sas_hdd_wc_ok,
                     'device_info': {
                         hctl: [size_val, size_unit, logsec, model, wwn,
                                mapping_state, kname, sginfo_wce, megaraid_wce],
                         ...},
                    },
         'SAS_SSD': {
                     ...
                    },
         ...} if succeeded. Else, {}.
    """
    warncnt = 0
    if not ok_scsi_ctrlr_kv or isinstance(ok_scsi_ctrlr_kv, dict) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter ok_scsi_ctrlr_kv: {ok_scsi_ctrlr_kv}")
    if isinstance(os_devs, list) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter os_devs: {os_devs}")
    if isinstance(check_sata, bool) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter check_sata: {check_sata}")
    if warncnt != 0:
        return {}

    if check_sata is False:
        print(f"{INFO} is checking SAS device")
    else:
        print(f"{INFO} is checking SAS and SATA device")

    hctl_dtype_kv = map_hctl_to_disktype()
    if not hctl_dtype_kv:
        print(f"{INFO} does not have any disk attached to SCSI controller")
        return {}

    supp_ctrlr_lgcnms = get_supported_ctrlr_logicalname(ok_scsi_ctrlr_kv)
    blkdevs = list_block_device()
    if not blkdevs:
        return {}

    sas_hdds = []
    sas_ssds = []
    sata_hdds = []
    sata_ssds = []
    sas_hdd_kv = {}
    sas_ssd_kv = {}
    sata_hdd_kv = {}
    sata_ssd_kv = {}
    # Record disks attached to the unsupported SCSI controllers
    err_ctrlrlgcnm_dev_kv = {}
    errcnt = 0
    for bdev in blkdevs:
        hctl = ''
        size = ''
        logsec = ''
        model = ''
        wwn = ''
        kname = ''
        fstp = ''
        mntpnt = ''
        rota = -1
        state = ''
        try:
            hctl = bdev['hctl']
            size = bdev['size']
            logsec = bdev['log-sec']
            model = bdev['model']
            wwn = bdev['wwn']
            kname = bdev['kname']
            fstp = bdev['fstype']
            mntpnt = bdev['mountpoint']
            rota = int(bdev['rota'])
            state = bdev['state']
        except BaseException as e:
            errcnt += 1
            log.debug("Tried to extract items from %s but hit exception: %s",
                      bdev, e)
            print(f"{WARN} hit exception while extracting attributes of " +
                  "block device")
            continue
        if not hctl:
            # Skip if disk did not have H:T:C:L
            continue
        if not logsec:
            # Skip if disk did not have logical sector size
            log.debug("Got empty logsec from %s", bdev)
            print(f"{WARN} cannot get the logical sector size of a block " +
                  "device")
            continue
        if not model:
            # Skip if disk did not have model
            continue
        if not wwn:
            # Skip if disk did not have wwn
            continue
        if not kname:
            errcnt += 1
            log.debug("Got empty kname from %s", bdev)
            print(f"{WARN} cannot get the kname of a block device")
            continue
        if isinstance(rota, int) is False:
            errcnt += 1
            log.debug("Got invalid rota from %s", bdev)
            print(f"{WARN} cannot get valid rotation info of a block device")
            continue
        # Check if disk was OS installed
        if kname in os_devs:
            log.debug("get_available_block_device skips OS disk %s", kname)
            continue
        # Create decimal size and its unit
        size_unit = ''
        size_val = 0.0
        try:
            size_val = float(size[0:-1])
            raw_size_unit = size[-1]
            size_unit = f"{raw_size_unit}iB"
        except BaseException as e:
            errcnt += 1
            log.debug("Tried to extract device size from %s but hit exception: "
                      "%s", size, e)
            print(f"{WARN} hit exception while extracting the device size of " +
                  f"{kname}")
            continue
        if not size_unit or int(size_val) <= 0:
            log.debug("Tried to extract device size from %s but got size_unit: "
                      "%s, size_val: %s", size, size_unit, size_val)
            print(f"{WARN} cannot get size unit or size value of {kname}")
            continue
        if state not in ['running', 'live']:
            errcnt += 1
            state_cmd = 'lsblk -p -o kname,state'
            log.debug("Run: %s to show state of %s", state_cmd, kname)
            print(f"{WARN} has {kname} with {state} state which is not active")
            continue
        # Check if disk was attached to incorrect SCSI controller
        scsi_host = ''
        try:
            scsi_host = hctl.split(':', 1)[0].strip()
        except BaseException as e:
            errcnt += 1
            log.debug("Tried to extract host from %s but hit exception: %s",
                      hctl, e)
            print(f"{WARN} hit exception while extracting host from H:C:T:L")
            continue
        if not scsi_host:
            errcnt += 1
            log.debug("Cannot get host from %s", hctl)
            print(f"{WARN} cannot get host from H:C:T:L")
            continue
        ctrlr_lgcnm = f"scsi{scsi_host}"
        if ctrlr_lgcnm not in supp_ctrlr_lgcnms:
            errcnt += 1
            try:
                _ = err_ctrlrlgcnm_dev_kv[ctrlr_lgcnm]
            except KeyError:
                err_ctrlrlgcnm_dev_kv[ctrlr_lgcnm] = []
            err_ctrlrlgcnm_dev_kv[ctrlr_lgcnm].append(kname)
            continue
        # Check if disk was mounted
        if mntpnt:
            errcnt += 1
            print(f"{WARN} has {kname} mounted to {mntpnt} that cannot be " +
                  "used by ECE")
            continue
        devtype = ''
        try:
            devtype = hctl_dtype_kv[hctl]
        except KeyError as e:
            log.debug("Tried to extract disk type of %s %s but hit KeyError: "
                      "%s", hctl, kname, e)
            if fstp:
                print(f"{WARN} has {kname} which has been formatted as {fstp}" +
                      "file system")
            else:
                print(f"{WARN} has {kname} which is not a traditional disk")
                errcnt += 1
            continue
        mapping_state = 'mapping_success'
        if devtype == 'SCSI Disk' and rota == 1:
            sas_hdds.append(kname)
            sas_hdd_kv[hctl] = [size_val, size_unit, logsec, model, wwn,
                                mapping_state, kname]
        elif devtype == 'SCSI Disk' and rota == 0:
            sas_ssds.append(kname)
            sas_ssd_kv[hctl] = [size_val, size_unit, logsec, model, wwn,
                                mapping_state, kname]
        elif devtype == 'ATA Disk' and rota == 1:
            sata_hdds.append(kname)
            sata_hdd_kv[hctl] = [size_val, size_unit, logsec, model, wwn,
                                 mapping_state, kname]
        elif devtype == 'ATA Disk' and rota == 0:
            sata_ssds.append(kname)
            sata_ssd_kv[hctl] = [size_val, size_unit, logsec, model, wwn,
                                 mapping_state, kname]

    if err_ctrlrlgcnm_dev_kv:
        for lgcnm, devs in err_ctrlrlgcnm_dev_kv.items():
            log.debug("%s is attached to unsupported SCSI controller whose "
                      "logical name is %s", devs, lgcnm)
            for dev in devs:
                debugcmd = f"lshw -c disk -quiet |grep {dev} -B1"
                log.debug("To get more info of %s, run: %s", dev, debugcmd)
            dev_str = ", ".join(devs)
            print(f"{WARN} has {dev_str} attached to unsupported SCSI " +
                  f"controller whose logical name is {lgcnm}")

    all_dev_kv = {}
    if not sas_hdds:
        all_dev_kv['SAS_HDD'] = {}
        print(f"{INFO} does not have any proper SAS HDD to be used by ECE")
    else:
        sas_hdd_str = ", ".join(sas_hdds)
        print(f"{INFO} has SAS HDD {sas_hdd_str} that can be used by ECE")
        log.debug("SAS HDD")
        sas_hdd_wc_ok, sas_hdd_kv = check_write_cache_of_scsi_dev(sas_hdd_kv)
        log.debug("End SAS HDD")
        if sas_hdd_wc_ok is False:
            print(f"{WARN} Write Cache of SAS HDD[s] should be disabled")
        all_dev_kv['SAS_HDD'] = {'write_cache_ok': sas_hdd_wc_ok,
                                 'device_info': sas_hdd_kv}

    if not sas_ssds:
        all_dev_kv['SAS_SSD'] = {}
        print(f"{INFO} does not have any proper SAS SSD to be used by ECE")
    else:
        sas_ssd_str = ", ".join(sas_ssds)
        print(f"{INFO} has SAS SSD {sas_ssd_str} that can be used by ECE")
        log.debug("SAS SSD")
        sas_ssd_wc_ok, sas_ssd_kv = check_write_cache_of_scsi_dev(sas_ssd_kv)
        log.debug("End SAS SSD")
        if sas_ssd_wc_ok is False:
            print(f"{WARN} Write Cache of SAS SSD[s] should be disabled")
        all_dev_kv['SAS_SSD'] = {'write_cache_ok': sas_ssd_wc_ok,
                                 'device_info': sas_ssd_kv}

    if not sata_hdds:
        if check_sata is True:
            all_dev_kv['SATA_HDD'] = {}
            print(f"{INFO} does not have any proper SATA HDD to be used by ECE")
    else:
        sata_hdd_str = ", ".join(sata_hdds)
        log.debug("%s has SATA HDD: %s", HOSTNAME, sata_hdd_str)
        if check_sata is False:
            print(f"{WARN} has SATA HDD {sata_hdd_str} that cannot be used " +
                  "by ECE")
        else:
            log.debug("SATA HDD")
            is_sata_ok = check_sata_device(sata_hdds)
            log.debug("End SATA HDD")
            all_dev_kv['SATA_HDD'] = {'sata_setting_ok': is_sata_ok,
                                      'device_info': sata_hdd_kv}
            if is_sata_ok is True:
                print(f"{WARN} has SATA HDD {sata_hdd_str} that can be used " +
                      "by ECE")
            else:
                print(f"{WARN} has SATA HDD {sata_hdd_str} but not all of " +
                      "them passed the SATA setting checks")

    if not sata_ssds:
        if check_sata is True:
            all_dev_kv['SATA_SSD'] = {}
            print(f"{INFO} does not have any proper SATA SSD to be used by ECE")
    else:
        sata_ssd_str = ", ".join(sata_ssds)
        log.debug("%s has SATA SSD: %s", HOSTNAME, sata_ssd_str)
        if check_sata is False:
            print(f"{WARN} has SATA SSD {sata_ssd_str} that cannot be used " +
                  "by ECE")
        else:
            log.debug("SATA SSD")
            is_sata_ok = check_sata_device(sata_ssds)
            log.debug("End SATA SSD")
            all_dev_kv['SATA_SSD'] = {'sata_setting_ok': is_sata_ok,
                                      'device_info': sata_ssd_kv}
            if is_sata_ok is True:
                print(f"{WARN} has SATA SSD {sata_ssd_str} that can be used " +
                      "by ECE")
            else:
                print(f"{WARN} has SATA SSD {sata_ssd_str} but not all of " +
                      "them passed the SATA setting checks")

    return all_dev_kv


def convert_to_bytes(size: int, unit: str) -> int:
    """Convert size + unit to size in bytes.
    Args:
        size:
        unit: unit of size.
    Returns:
        size in bytes if succeeded. Else, -1.
    """
    errcnt = 0
    units = ['KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB']
    if isinstance(size, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter size: {size}")
    if not unit or isinstance(unit, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter unit: {unit}")
    elif unit not in units:
        errcnt += 1
        print(f"{ERROR} parameter unit should be chosen from: {units}")
    if errcnt != 0:
        return -1

    # unit conversion coefficient dict
    unit_coef_kv = {"KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
                    "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "TiB": 2**40}

    size_in_bytes = -1
    # Would not hit KeyError here. unit is well checked
    size_in_bytes = size * unit_coef_kv[unit]
    log.debug("Converted %s %s to %s Bytes", size, unit, size_in_bytes)
    return size_in_bytes


def check_ssd_loghome_size(
        ssd_kv: Dict,
        min_loghome_size: int) -> bool:
    """Check if loghome could be built on SSDs.
    Args:
        ssd_kv: {'hctl': [size_val, size_unit, logsec, model, wwn,
                          mapping_state, kname, sginfo_wce, megaraid_wce],
                 ...}
        min_loghome_size: MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json.
    Returns:
        True if size of SSD met the requirement. Else, False.
    """
    warncnt = 0
    if not ssd_kv or isinstance(ssd_kv, dict) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter ssd_kv: {ssd_kv}")
    if isinstance(min_loghome_size, int) is False:
        warncnt += 1
        print(f"{WARN} Invalid parameter min_loghome_size: {min_loghome_size}")
    if warncnt != 0:
        return False

    size_ok = False
    for key, val in ssd_kv.items():
        int_capacity = 0
        capacity_unit = ''
        try:
            int_capacity = int(float(val[0]))
            capacity_unit = val[1]
        except BaseException as e:
            log.debug("Tried to extract SSD capacity from %s: %s but hit "
                      "exception: %s", key, val, e)
            print(f"{WARN} hit exception while extracting SSD capacity of " +
                  f"{key}")
            continue
        if not int_capacity or not capacity_unit:
            log.debug("Size of %s: %s is %s %s", key, val, int_capacity,
                      capacity_unit)
            print(f"{WARN} cannot get SSD capacity of {key}")
            continue
        cap_in_bytes = convert_to_bytes(int_capacity, capacity_unit)
        if cap_in_bytes >= min_loghome_size:
            size_ok = True
            break

    log.debug("Can loghome built on SSD? %s", size_ok)
    return size_ok


def set_megaraid_tool(check_pkg: bool) -> bool:
    """Set MegaRAID tool according to the server vendor.
    Args:
        check_pkg: will check the installation state if set True
    Returns:
        True if successfully set SAS tool. Else, False.
    """
    global MSM_NAME
    global MSM_APP
    if isinstance(check_pkg, bool) is False:
        print(f"{WARN} Invalid parameter check_pkg: {check_pkg}")
        return False

    cmd = 'dmidecode --string system-manufacturer'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while querying system manufacturer")
        print(f"{WARN} cannot set MegaRAID tool")
        return False
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{WARN} hit error while querying system manufacturer")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        return False
    if rc == 0 and not out.strip():
        log.debug("Ran: %s. Got empty stdout", cmd)
        print(f"{WARN} got empty system manufacturer")
        return False

    vendor = out.strip()
    log.debug("Got system manufacturer: %s", vendor)
    if vendor and vendor.startswith('Dell Inc.'):
        MSM_NAME = 'perccli'
        MSM_APP = '/opt/MegaRAID/perccli/perccli64'
    else:
        MSM_NAME = 'storcli'
        MSM_APP = '/opt/MegaRAID/storcli/storcli64'
    print(f"{INFO} sets MegaRAID tool to '{MSM_APP}'")

    is_exe = False
    if os.path.exists(MSM_APP) is True and os.access(MSM_APP, os.X_OK) is True:
        is_exe = True
    log.debug("Is %s executable? %s", MSM_APP, is_exe)

    if check_pkg is True:
        if is_exe is True:
            print(f"{INFO} MegaRAID tool is available")
        else:
            print(f"{WARN} MegaRAID tool is NOT available")
        return is_exe
    else:
        print(f"{WARN} ignores MegaRAID tool installation state checking. " +
              "Suppose it has been installed")
        if is_exe is False:
            log.debug("In fact, %s is not available", MSM_APP)
        return True


def check_physical_storage(
        pci_kv: Dict,
        supp_scsi_ctrlr_kv: Dict,
        min_loghome_size: int,
        max_dev_num: int,
        check_pkg: bool,
        check_sata: bool=False) -> Dict[str, Any]:
    """Check physical storage controller and devices.
    Args:
        pci_kv: output of lspci.
        supp_scsi_ctrlr_kv: SAS controller supported in SAS_adapters.json.
        min_loghome_size: MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json.
        max_dev_num: MAX_DRIVES in HW_requirements.json.
        check_pkg: enable nvme-cli package check.
        check_sata: enable SATA device check.
    Returns:
        storage KV pair if succeeded. Else, {}.
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_scsi_ctrlr_kv or isinstance(supp_scsi_ctrlr_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_scsi_ctrlr_kv: " +
              f"{supp_scsi_ctrlr_kv}")
    if isinstance(min_loghome_size, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_loghome_size: {min_loghome_size}")
    if isinstance(max_dev_num, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter max_dev_num: {max_dev_num}")
    if isinstance(check_pkg, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter check_pkg: {check_pkg}")
    if isinstance(check_sata, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter check_sata: {check_sata}")
    if errcnt != 0:
        print(f"{ERROR} cannot check storage device")
        return {}

    scsi_ctrlr_ok = False
    is_mega_inst = False
    hdd_kv = {}
    ssd_kv = {}
    hdd_dev_num = 0
    ssd_dev_num = 0
    hdd_wc_ok = False
    ssd_wc_ok = False
    sata_hdd_setting_ok = False
    sata_ssd_setting_ok = False
    nvme_dev_num = 0
    valid_dev_num = 0
    # hdd_fatal_error is not important because ECE can be setup
    # on NVMe or SSD
    hdd_fatal_error = False
    ssd_fatal_error = False
    ssd_loghome_ok = False
    nvme_loghome_ok = False
    loghome_error = True
    ctrlr_ok_but_no_dev = False

    scsi_ctrlr_kv = mark_physical_scsi_controller(pci_kv, supp_scsi_ctrlr_kv)

    stor_kv = {}
    ok_scsi_ctrlrs = []
    ok_scsi_ctrlr_kv = {}
    for key, val in scsi_ctrlr_kv.items():
        if '[OK]' in val:
            scsi_ctrlr_name = val.replace(' [OK]', '')
            ok_scsi_ctrlrs.append(scsi_ctrlr_name)
            ok_scsi_ctrlr_kv[key] = val
    stor_kv['SCSI_controllers'] = ok_scsi_ctrlrs

    blkdevs = list_block_device()
    if not blkdevs:
        return {}
    os_disks = get_os_disk(blkdevs)

    if ok_scsi_ctrlrs:
        scsi_ctrlr_ok = True
        megaraid_sas_dev_num = 0
        megaraid_sata_dev_num = 0

        is_mega_inst = set_megaraid_tool(check_pkg)
        if is_mega_inst is False:
            print(f"{WARN} MegaRAID Storage Manager tool is required")
        else:
            print(f"{INFO} MegaRAID tool is querying the device information " +
                  "it manages...")
            call_cmd = f"{MSM_APP} /call show all j"
            call_out, err, rc = runcmd(call_cmd, True)
            log.debug("Ran: %s. Got stderr: %s, return code: %d", call_cmd, err,
                      rc)
            stor_kv['MegaRAID_tool_call'] = json.loads(call_out)
            calleall_cmd = f"{MSM_APP} /call/eall show all j"
            calleall_out, err, rc = runcmd(calleall_cmd, True)
            log.debug("Ran: %s. Got stderr: %s, return code: %d", calleall_cmd,
                      err, rc)
            stor_kv['MegaRAID_tool_call_eall'] = json.loads(calleall_out)
            ces_cmd = f"{MSM_APP} /call/eall/sall show all j"
            ces_out, err, rc = runcmd(ces_cmd, True)
            log.debug("Ran: %s. Got stderr: %s, return code: %d", ces_cmd, err,
                      rc)
            stor_kv['MegaRAID_tool_call_eall_sall'] = json.loads(ces_out)

            lspci_ctrlr_num = len(scsi_ctrlr_kv)
            # storcli management
            mega_ctrlr_num = get_controller_number_by_megaraid_tool()
            need_to_run_stortool = False
            if mega_ctrlr_num > 0:
                if lspci_ctrlr_num != mega_ctrlr_num:
                    print(f"{WARN} lspci detected {lspci_ctrlr_num} SAS/SATA " +
                          "controller[s] but MegaRAID managed " +
                          f"{mega_ctrlr_num} controller[s]")
                if_types = get_scsi_controller_interface_types()
                if not if_types:
                    need_to_run_stortool = True
                else:
                    type_len = len(if_types)
                    log.debug("Got type_len: %d, mega_ctrlr_num: %d", type_len,
                              mega_ctrlr_num)
                    if type_len != mega_ctrlr_num:
                        need_to_run_stortool = True
                        print(f"{WARN} MegaRAID tool got {type_len} Device " +
                              "Interface types but got Number of " +
                              f"Controllers: {0}")
                    else:
                        allok = all(OK_DEVIF_TYPE == i for i in if_types)
                        anyok = any(OK_DEVIF_TYPE == i for i in if_types)
                        interface_ok = 'none'
                        if allok is True:
                            # All SCSI Controllers have OK_DEVIF_TYPE
                            interface_ok = 'all'
                        else:
                            if anyok is True:
                                # Partial SCSI Controllers have OK_DEVIF_TYPE
                                need_to_run_stortool = True
                                interface_ok = 'partial'
                            else:
                                need_to_run_stortool = True
                                interface_ok = 'none'
                        if interface_ok == 'all':
                            print(f"{INFO} has {mega_ctrlr_num} " +
                                  f"{OK_DEVIF_TYPE} Controller[s]")
                        elif interface_ok == 'partial':
                            print(f"{WARN} has {mega_ctrlr_num} SCSI " +
                                  "Controllers but NOT all of them " +
                                  f"have {OK_DEVIF_TYPE} interface")
                        elif interface_ok == 'none':
                            print(f"{WARN} has {mega_ctrlr_num} SCSI " +
                                  "Controller[s] but none of them has " +
                                  f"{OK_DEVIF_TYPE} interface")
            if need_to_run_stortool is True:
                print(f"{INFO} needs to run {STOR_TOOL}")
            cmd = f"{MSM_APP} /call show"
            try:
                out, err, rc = runcmd(cmd)
            except BaseException as e:
                log.debug("Ran: %s. Hit exception: %s", cmd, e)
                print(f"{WARN} hit exception while running MegaRAID tool")
            if rc != 0:
                log.debug("Ran: %s. Got return code: %d", cmd, rc)
                print(f"{WARN} hit error while running MegaRAID tool")
                if err.strip():
                    log.debug("Ran: %s. Got error: %s", cmd, err)
            out = out.strip()
            if rc == 0 and not out:
                errcnt += 1
                log.debug("Ran: %s. Got empty stdout", cmd)
                print(f"{WARN} got empty stdout while running MegaRAID tool")

            sas_lines = []
            sata_lines = []
            if rc == 0 and out:
                for line in out.splitlines():
                    if ('JBOD' not in line) and ('UGood' not in line):
                        continue
                    if 'SAS' in line:
                        sas_lines.append(line.strip())
                    elif 'SATA' in line:
                        sata_lines.append(line.strip())
            sas_lines = list(set(sas_lines))
            sata_lines = list(set(sata_lines))
            megaraid_sas_dev_num = len(sas_lines)
            megaraid_sata_dev_num = len(sata_lines)
            log.debug("Got megaraid_sas_dev_num: %d, megaraid_sata_dev_num: %d",
                      megaraid_sas_dev_num, megaraid_sata_dev_num)

        lsblk_sas_dev_num = 0
        lsblk_sata_dev_num = 0
        sas_hdd_kv = {}
        sas_ssd_kv = {}
        sata_hdd_kv = {}
        sata_ssd_kv = {}
        all_dev_kv = get_available_block_device(
                         ok_scsi_ctrlr_kv,
                         os_disks,
                         check_sata)
        if all_dev_kv:
            sas_hdd_top_kv = {}
            sas_ssd_top_kv = {}
            sata_hdd_top_kv = {}
            sata_ssd_top_kv = {}
            try:
                sas_hdd_top_kv = all_dev_kv['SAS_HDD']
            except KeyError:
                pass
            try:
                sas_ssd_top_kv = all_dev_kv['SAS_SSD']
            except KeyError:
                pass
            try:
                sata_hdd_top_kv = all_dev_kv['SATA_HDD']
            except KeyError:
                pass
            try:
                sata_ssd_top_kv = all_dev_kv['SATA_SSD']
            except KeyError:
                pass
            if sas_hdd_top_kv:
                try:
                    hdd_wc_ok = sas_hdd_top_kv['write_cache_ok']
                    sas_hdd_kv = sas_hdd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SAS HDD info but hit KeyError: "
                              "%s", e)
                    print(f"{WARN} hit exception while extracting SAS HDD " +
                          "information")
            if sas_ssd_top_kv:
                try:
                    ssd_wc_ok = sas_ssd_top_kv['write_cache_ok']
                    sas_ssd_kv = sas_ssd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SAS SSD info but hit KeyError: "
                              "%s", e)
                    print(f"{WARN} hit exception while extracting SAS SSD " +
                          "information")
            if sata_hdd_top_kv:
                try:
                    sata_hdd_setting_ok = sata_hdd_top_kv['sata_setting_ok']
                    sata_hdd_kv = sata_hdd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SATA HDD info but hit "
                              "KeyError: %s", e)
                    print(f"{WARN} hit exception while extracting SATA HDD " +
                          "information")
            if sata_ssd_top_kv:
                try:
                    sata_ssd_setting_ok = sata_ssd_top_kv['sata_setting_ok']
                    sata_ssd_kv = sata_ssd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SATA SSD info but hit "
                              "KeyError: %s", e)
                    print(f"{WARN} hit exception while extracting SATA SSD " +
                          "information")
            lsblk_sas_dev_num = len(sas_hdd_kv) + len(sas_ssd_kv)
            lsblk_sata_dev_num = len(sata_hdd_kv) + len(sata_ssd_kv)
            log.debug("Got lsblk_sas_dev_num: %d, lsblk_sata_dev_num: %d",
                      lsblk_sas_dev_num, lsblk_sata_dev_num)

        if megaraid_sas_dev_num > 0 and lsblk_sas_dev_num > 0:
            if megaraid_sas_dev_num >= lsblk_sas_dev_num:
                print(f"{INFO} It seems all SAS storage devices are managed " +
                      "by the MegaRAID tool")
            else:
                print(f"{WARN} not all SAS storage devices are managed by " +
                      "MegaRAID tool")
        if check_sata is True and \
           megaraid_sata_dev_num > 0 and lsblk_sata_dev_num > 0:
            if megaraid_sata_dev_num >= lsblk_sata_dev_num:
                print(f"{INFO} It seems all SATA storage devices are managed " +
                      "by the MegaRAID tool")
            else:
                print(f"{WARN} not all SATA storage devices are managed by " +
                      "MegaRAID tool")

        hdd_kv = sas_hdd_kv
        ssd_kv = sas_ssd_kv
        hdd_dev_num = len(hdd_kv)
        ssd_dev_num = len(ssd_kv)
        if hdd_dev_num < 1:
            hdd_fatal_error = True
        else:
            hdd_fatal_error = False
        if ssd_dev_num < 1:
            ssd_fatal_error = True
        else:
            ssd_fatal_error = False

        if hdd_fatal_error is False and hdd_wc_ok is True:
            valid_dev_num += hdd_dev_num
            print(f"{INFO} has a total of {hdd_dev_num} SAS HDD[s] that can " +
                  "be used by ECE")
        if check_sata is True:
            sata_hdd_num = len(sata_hdd_kv)
            if sata_hdd_num > 0 and sata_hdd_setting_ok is True:
                print(f"{WARN} has a total of {sata_hdd_num} SATA HDD[s] but " +
                      "it is not recommended to use")
        if ssd_fatal_error is False and ssd_wc_ok is True:
            print(f"{INFO} has a total of {ssd_dev_num} SAS SSD[s] that can " +
                  "be used by ECE")
            ssd_loghome_ok = check_ssd_loghome_size(ssd_kv, min_loghome_size)
        if check_sata is True:
            sata_ssd_num = len(sata_ssd_kv)
            if sata_ssd_num > 0 and sata_ssd_setting_ok is True:
                print(f"{WARN} has a total of {sata_ssd_num} SATA SSD[s] but " +
                      "it is not recommended to use")

        if hdd_dev_num > 0 or ssd_dev_num > 0:
            ctrlr_ok_but_no_dev = False
        else:
            ctrlr_ok_but_no_dev = True
        log.debug("Got ctrlr_ok_but_no_dev: %s", ctrlr_ok_but_no_dev)

    stor_kv['Is_SCSI_controller_OK'] = scsi_ctrlr_ok
    stor_kv['Is_MegaRAID_package_installed'] = is_mega_inst
    stor_kv['HDD_error'] = hdd_fatal_error
    stor_kv['HDD_device_number'] = hdd_dev_num
    stor_kv['HDD_KV'] = hdd_kv
    stor_kv['HDD_Write_Cache_Disabled'] = hdd_wc_ok
    stor_kv['SSD_error'] = ssd_fatal_error
    stor_kv['SSD_device_number'] = ssd_dev_num
    stor_kv['SSD_KV'] = ssd_kv
    stor_kv['SSD_Write_Cache_Disabled'] = ssd_wc_ok
    stor_kv['SCSI_controller_ok_but_no_device'] = ctrlr_ok_but_no_dev

    # Check NVMe drive
    nvme_err = False
    nvme_dev_num = get_nvme_drive_num()
    if nvme_dev_num == -1:
        nvme_err = True
        nvme_dev_num = 0

    nvme_kv = {}
    nvme_id_kv = {}
    is_nvmecli_inst = False
    nvme_info_err = False
    nvme_wce_err = False
    nvme_lba_err = False
    nvme_md_err = True
    nvme_id_err = True
    if nvme_err is False:
        is_nvmecli_inst = is_nvmecli_installed(check_pkg)
    if is_nvmecli_inst is False:
        nvme_err = True
    else:
        nvme_info_err, nvme_kv = get_nvme_info()
        if nvme_info_err is True or not nvme_kv:
            nvme_err = True
            nvme_dev_num = 0

    if is_nvmecli_inst is True and nvme_kv:
        # Renew nvme_kv
        nvme_wce_err, nvme_kv = check_nvme_vwc(nvme_kv)
        #if nvme_wce_err is True:
        #    nvme_err = True
        #    errcnt += 1
        is_lba_ok = check_nvme_inuse_lbads(nvme_kv)
        if is_lba_ok is True:
            nvme_lba_err = False
        else:
            nvme_lba_err = True
        is_ms_ok = check_nvme_inuse_ms(nvme_kv)
        if is_ms_ok is True:
            nvme_md_err = False
        else:
            nvme_md_err = True
        nvme_id_err, nvme_id_kv = get_nvme_eui_nguid(nvme_kv)
        if nvme_id_err is True:
            errcnt += 1
        nvme_loghome_ok = check_nvme_loghome_size(nvme_kv, min_loghome_size)

    if nvme_loghome_ok is True or ssd_loghome_ok is True:
        loghome_error = False
        # All solid disk checks completed
        if nvme_dev_num > 0:
            valid_dev_num += nvme_dev_num
        if ssd_dev_num > 0:
            valid_dev_num += ssd_dev_num

    stor_kv['NVMe_error'] = nvme_err
    stor_kv['NVMe_drive_number'] = nvme_dev_num
    stor_kv['Is_nvmecli_installed'] = is_nvmecli_inst
    stor_kv['NVMe_WCE_error'] = nvme_wce_err
    stor_kv['NVMe_LBA_error'] = nvme_lba_err
    stor_kv['NVMe_MD_error'] = nvme_md_err
    stor_kv['NVMe_ID_error'] = nvme_id_err
    stor_kv['NVMe_info_KV'] = nvme_kv
    stor_kv['NVMe_ID_KV'] = nvme_id_kv
    stor_kv['loghome_error'] = loghome_error
    stor_kv['valid_storage_device_number'] = valid_dev_num

    if loghome_error is True:
        errcnt += 1
        print(f"{ERROR} does not have any solid state drive whose capacity " +
             f"met the minimum {min_loghome_size} Bytes that loghome size " +
             "required")

    if ctrlr_ok_but_no_dev is True:
        print(f"{WARN} has supported SCSI controller but no proper device is " +
              "attached to it")

    if nvme_err is True:
        print(f"{WARN} has NVMe drive issue")

    if ssd_fatal_error is True and nvme_err is True:
        errcnt += 1
        print(f"{ERROR} does not have any proper NVMe drive or SSD can be " +
              "used by ECE. At least one NVMe drive or SSD is required")
    else:
        if valid_dev_num > max_dev_num:
            errcnt += 1
            print(f"{ERROR} has a total of {valid_dev_num} storage devices " +
                  f"that exceeds the maximum {max_dev_num} disks per node " +
                  "that ECE restricts")
        else:
            print(f"{INFO} has a total of {valid_dev_num} disk[s] that can " +
                  "be used by ECE")
    stor_kv['storage_errcnt'] = errcnt

    #log.debug("Generated stor_kv: %s", stor_kv)
    return stor_kv


def check_vmware_storage(
        pci_kv: Dict,
        supp_scsi_ctrlr_kv: Dict,
        min_loghome_size: int,
        max_dev_num: int,
        check_pkg: bool,
        check_sata: bool=False) -> Dict[str, Any]:
    """Check VMware storage controller and devices.
    Args:
        pci_kv: output of lspci.
        supp_scsi_ctrlr_kv: SAS controller supported in SAS_adapters.json.
        min_loghome_size: MIN_LOGHOME_DRIVE_SIZE in HW_requirements.json.
        max_dev_num: MAX_DRIVES in HW_requirements.json.
        check_pkg: enable nvme-cli package check.
        check_sata: enable SATA device check.
                    False(default)|True(Not supported at present).
    Returns:
        storage KV pair if succeeded. Else, {}.
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_scsi_ctrlr_kv or isinstance(supp_scsi_ctrlr_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_scsi_ctrlr_kv: " +
              f"{supp_scsi_ctrlr_kv}")
    if isinstance(min_loghome_size, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_loghome_size: {min_loghome_size}")
    if isinstance(max_dev_num, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter max_dev_num: {max_dev_num}")
    if isinstance(check_pkg, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter check_pkg: {check_pkg}")
    if isinstance(check_sata, bool) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter check_sata: {check_sata}")
    if check_sata is True:
        errcnt += 1
        print(f"{ERROR} SATA device is not supported by ECE in VMWare " +
              "environment at present")
    if errcnt != 0:
        print(f"{ERROR} cannot check storage device")
        return {}

    scsi_ctrlr_kv = mark_vmware_scsi_controller(
                       pci_kv,
                       supp_scsi_ctrlr_kv)
    log.debug("Called mark_vmware_scsi_controller, got "
              "scsi_ctrlr_kv: %s", scsi_ctrlr_kv)
    if not scsi_ctrlr_kv:
        return {}

    scsi_ctrlr_ok = False
    hdd_kv = {}
    ssd_kv = {}
    hdd_dev_num = 0
    ssd_dev_num = 0
    hdd_wc_ok = False
    ssd_wc_ok = False
    nvme_dev_num = 0
    valid_dev_num = 0
    # hdd_fatal_error is not important because ECE can be setup
    # on NVMe or SSD
    hdd_fatal_error = False
    ssd_fatal_error = False
    ssd_loghome_ok = False
    nvme_loghome_ok = False
    loghome_error = True
    ctrlr_ok_but_no_dev = False
    stor_kv = {}
    # SAS card error is from MegaRAID tool checking. For VMWare,
    # set it to Fasle
    stor_kv['MegaRAID_package_error'] = False

    ok_scsi_ctrlrs = []
    ok_scsi_ctrlr_kv = {}
    for key, val in scsi_ctrlr_kv.items():
        if '[OK]' in val:
            scsi_ctrlr_name = val.replace(' [OK]', '')
            ok_scsi_ctrlrs.append(scsi_ctrlr_name)
            ok_scsi_ctrlr_kv[key] = val
    stor_kv['SCSI_controllers'] = ok_scsi_ctrlrs

    blkdevs = list_block_device()
    if not blkdevs:
        return {}
    os_disks = get_os_disk(blkdevs)

    if ok_scsi_ctrlrs:
        scsi_ctrlr_ok = True
        all_dev_kv = get_available_block_device(ok_scsi_ctrlr_kv, os_disks)
        if not all_dev_kv:
            hdd_fatal_error = True
            ssd_fatal_error = True
            hdd_wc_ok = False
            ssd_wc_ok = False
            hdd_dev_num = 0
            ssd_dev_num = 0
        else:
            hdd_top_kv = {}
            ssd_top_kv = {}
            try:
                hdd_top_kv = all_dev_kv['SAS_HDD']
            except KeyError:
                pass
            try:
                ssd_top_kv = all_dev_kv['SAS_SSD']
            except KeyError:
                pass
            if hdd_top_kv:
                try:
                    hdd_wc_ok = hdd_top_kv['write_cache_ok']
                    hdd_kv = hdd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SAS HDD info but hit KeyError: "
                              "%s", e)
                    print(f"{WARN} hit exception while extracting SAS HDD " +
                          "information")
            if ssd_top_kv:
                try:
                    ssd_wc_ok = ssd_top_kv['write_cache_ok']
                    ssd_kv = ssd_top_kv['device_info']
                except KeyError as e:
                    log.debug("Tried to extract SAS SSD info but hit KeyError: "
                              "%s", e)
                    print(f"{WARN} hit exception while extracting SAS SSD " +
                          "information")
            hdd_dev_num = len(hdd_kv)
            ssd_dev_num = len(ssd_kv)
        if hdd_dev_num < 1:
            hdd_fatal_error = True
        else:
            hdd_fatal_error = False
        if ssd_dev_num < 1:
            ssd_fatal_error = True
        else:
            ssd_fatal_error = False

        if hdd_fatal_error is False and hdd_wc_ok is True:
            valid_dev_num += hdd_dev_num
            print(f"{INFO} has a total of {hdd_dev_num} SAS HDD[s] that can " +
                  "be used by ECE")
        if ssd_fatal_error is False and ssd_wc_ok is True:
            print(f"{INFO} has a total of {ssd_dev_num} SAS SSD[s] that can " +
                  "be used by ECE")
            ssd_loghome_ok = check_ssd_loghome_size(ssd_kv, min_loghome_size)

        if hdd_dev_num > 0 or ssd_dev_num > 0:
            ctrlr_ok_but_no_dev = False
        else:
            ctrlr_ok_but_no_dev = True
        log.debug("Generate ctrlr_ok_but_no_dev: %s", ctrlr_ok_but_no_dev)

    stor_kv['Is_SCSI_controller_OK'] = scsi_ctrlr_ok
    stor_kv['HDD_error'] = hdd_fatal_error
    stor_kv['HDD_device_number'] = hdd_dev_num
    stor_kv['HDD_KV'] = hdd_kv
    stor_kv['HDD_Write_Cache_Disabled'] = hdd_wc_ok
    stor_kv['SSD_error'] = ssd_fatal_error
    stor_kv['SSD_device_number'] = ssd_dev_num
    stor_kv['SSD_KV'] = ssd_kv
    stor_kv['SSD_Write_Cache_Disabled'] = ssd_wc_ok
    stor_kv['SCSI_controller_ok_but_no_device'] = ctrlr_ok_but_no_dev

    # Check NVMe drive
    nvme_err = False
    nvme_dev_num = get_nvme_drive_num()
    if nvme_dev_num == -1:
        nvme_err = True
        nvme_dev_num = 0

    nvme_kv = {}
    nvme_id_kv = {}
    is_nvmecli_inst = False
    nvme_info_err = False
    nvme_wce_err = False
    nvme_lba_err = False
    nvme_md_err = True
    nvme_id_err = True
    if nvme_err is False:
        is_nvmecli_inst = is_nvmecli_installed(check_pkg)
    if is_nvmecli_inst is False:
        nvme_err = True
    else:
        # Renew nvme_err
        nvme_info_err, nvme_kv = get_nvme_info()
        if nvme_info_err is True or not nvme_kv:
            nvme_err = True
            nvme_dev_num = 0

    if is_nvmecli_inst is True and nvme_kv:
        # Renew nvme_kv
        nvme_wce_err, nvme_kv = check_nvme_vwc(nvme_kv)
        #if nvme_wce_err is True:
        #    nvme_err = True
        #    errcnt += 1
        is_lba_ok = check_nvme_inuse_lbads(nvme_kv)
        if is_lba_ok is True:
            nvme_lba_err = False
        else:
            nvme_lba_err = True
        is_ms_ok = check_nvme_inuse_ms(nvme_kv)
        if is_ms_ok is True:
            nvme_md_err = False
        else:
            nvme_md_err = True
        nvme_id_err, nvme_id_kv = get_nvme_eui_nguid(nvme_kv)
        if nvme_id_err is True:
            errcnt += 1
        nvme_loghome_ok = check_nvme_loghome_size(nvme_kv, min_loghome_size)

    if nvme_loghome_ok is True or ssd_loghome_ok is True:
        loghome_error = False
        # All solid disk checks completed
        if nvme_dev_num > 0:
            valid_dev_num += nvme_dev_num
        if ssd_dev_num > 0:
            valid_dev_num += ssd_dev_num

    stor_kv['NVMe_error'] = nvme_err
    stor_kv['NVMe_drive_number'] = nvme_dev_num
    stor_kv['Is_nvmecli_installed'] = is_nvmecli_inst
    stor_kv['NVMe_WCE_error'] = nvme_wce_err
    stor_kv['NVMe_LBA_error'] = nvme_lba_err
    stor_kv['NVMe_MD_error'] = nvme_md_err
    stor_kv['NVMe_ID_error'] = nvme_id_err
    stor_kv['NVMe_info_KV'] = nvme_kv
    stor_kv['NVMe_ID_KV'] = nvme_id_kv
    stor_kv['loghome_error'] = loghome_error
    stor_kv['valid_storage_device_number'] = valid_dev_num

    if loghome_error is True:
        errcnt += 1
        print(f"{ERROR} does not have any solid state drive whose capacity " +
              f"met the minimum {min_loghome_size} Bytes that loghome size " +
              "required")

    if ctrlr_ok_but_no_dev is True:
        print(f"{WARN} has supported SCSI controller but no proper device is " +
              "attached to it")

    if nvme_err is True:
        print(f"{WARN} has NVMe drive issue")

    if ssd_fatal_error is True and nvme_err is True:
        errcnt += 1
        print(f"{ERROR} does not have any proper NVMe drive or SSD can be " +
              "used by ECE. At least one NVMe drive or SSD is required")
    else:
        if valid_dev_num > max_dev_num:
            errcnt += 1
            print(f"{ERROR} has a total of {valid_dev_num} storage devices " +
                  f"that exceeds the maximum {max_dev_num} disks per node "
                  "that ECE restricts")
        else:
            print(f"{INFO} has a total of {valid_dev_num} disk[s] that can " +
                  "be used by ECE")
    stor_kv['storage_errcnt'] = errcnt

    #log.debug("Generated stor_kv: %s", stor_kv)
    return stor_kv


def mark_network_devicename(
        pci_kv: Dict,
        supp_nic_kv: Dict) -> Dict[str, str]:
    """Mark supporting state of network device.
    Args:
        pci_kv: output of lspci.
        scsi_ctrlr_kv: SCSI controller supported in SAS_adapters.json.
    Returns:
        {pciAddress: networkDeviceName, ...} if succeeded. Else, {}.
        like: {'86:00.0': 'Mellanox Technologies MT27800 Family [ConnectX-5] \
        [OK]'}
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_nic_kv or isinstance(supp_nic_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_nic_kv: {supp_nic_kv}")
    if errcnt != 0:
        return {}

    # Extract supported network interface cards
    supp_nics = []
    try:
        raw_nics = list(supp_nic_kv.keys())
        supp_nics = [str(i) for i in raw_nics if i != 'json_version']
    except BaseException as e:
        log.debug("Tried to extract supported NIC but hit exception: %s", e)
        print(f"{ERROR} hit exception while extracting supported NIC")
        return {}

    log.debug("Got supp_nics: %s", supp_nics)
    if not supp_nics:
        print(f"{ERROR} cannot get any supported NIC")
        return {}

    print(f"{INFO} is checking network device")
    # Get local NIC device as alternative NICs
    supp_nic_len = len(supp_nics)
    alt_pci_nic_kv = {}
    for key, val in pci_kv.items():
        pci_addr = key
        dev_type = val[0]
        dev_name = val[1]
        if dev_type != 'Ethernet controller' and \
           dev_type != 'Infiniband controller':
            continue
        if not pci_addr or not dev_name:
            continue
        alt_pci_nic_kv[pci_addr] = dev_name
    log.debug("Got alt_pci_nic_kv: %s", alt_pci_nic_kv)
    if not alt_pci_nic_kv:
        print(f"{ERROR} does not have any network controller")
        return {}

    # Marking
    marked_pci_nic_kv = {}
    ok_nics = []
    notok_nics = []
    reserved_nics = []
    nottested_nics = []
    for key, val in alt_pci_nic_kv.items():
        not_match_cnt = 0
        for supp_n in supp_nics:
            marker = 'Unknown'
            try:
                marker = supp_nic_kv[supp_n]
            except KeyError as e:
                log.debug("Tried to get marker of %s but hit KeyError: %s",
                          supp_n, e)
                print(f"{WARN} hit exception while extracting marker for " +
                      f"supported NIC: {supp_n}")
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            if not marker:
                marker = 'Unknown'
                log.debug("Got emtpy marker from %s", supp_nic_kv)
                print(f"{WARN} marks supporting state of {val} as [Unknown]")
            if supp_n in val:
                marked_name = ''
                if marker == 'OK':
                    marked_name = f"{val} [OK]"
                    ok_nics.append(val)
                elif marker == 'NOK':
                    marked_name = f"{val} [NOT OK]"
                    notok_nics.append(val)
                else:
                    marked_name = f"{val} [{marker}]"
                    reserved_nics.append(val)
                if marked_name:
                    marked_pci_nic_kv[key] = marked_name
            else:
                not_match_cnt += 1
        if not_match_cnt == supp_nic_len:
            marked_name = f"{val} [NOT TESTED]"
            nottested_nics.append(val)
            marked_pci_nic_kv[key] = marked_name
    log.debug("Got marked_pci_nic_kv: %s, ok_nics: %s, notok_nics: %s, "
              "reserved_nics: %s, nottested_nics: %s", marked_pci_nic_kv,
              ok_nics, notok_nics, reserved_nics, nottested_nics)
    if not marked_pci_nic_kv:
        print(f"{WARN} cannot mark network controller")
        return {}

    if ok_nics:
        ok_nic_len = len(ok_nics)
        if ok_nic_len == 1:
            print(f"{INFO} has following network controller tested by IBM")
        else:
            print(f"{INFO} has following network controllers tested by IBM")
        for ok_n in ok_nics:
            print(f"{INFO} {ok_n}")
    if notok_nics:
        notok_nic_len = len(notok_nics)
        if notok_nic_len == 1:
            print(f"{ERROR} has following network controller explicitly NOT " +
                  "supported by ECE")
        else:
            print(f"{ERROR} has following network controllers explicitly NOT " +
                  "supported by ECE")
        for notok_n in notok_nics:
            print(f"{ERROR} {notok_n}")
    if reserved_nics:
        rsvd_nic_len = len(reserved_nics)
        if rsvd_nic_len == 1:
            print(f"{WARN} has following network controller tagged by IBM")
        else:
            print(f"{WARN} has following network controllers tagged by IBM")
        for rsvd_n in reserved_nics:
            print(f"{WARN} {rsvd_n}")
    if nottested_nics:
        ntst_nic_len = len(nottested_nics)
        if ntst_nic_len == 1:
            print(f"{WARN} has following network controller NOT tested by IBM")
        else:
            print(f"{WARN} has following network controllers NOT tested by IBM")
        for ntst_n in nottested_nics:
            print(f"{WARN} {ntst_n}")

    return marked_pci_nic_kv


def map_network_pci_to_logicalname() -> Dict[str, str]:
    """Map PCI-E address to Network logical name.
    Args:
    Returns:
        {pciAddress: logicalName, ...} if succeeded. Else, {}.
        like: {'0000:3b:00.0': 'ib0', ...}
    """
    errcnt = 0
    cmd = 'lshw -class network -quiet'
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        errcnt += 1
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{WARN} hit exception while listing network hardware")
    if rc != 0:
        errcnt += 1
        print(f"{WARN} hit error while listing network hardware")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)

    if rc == 0 and not out.strip():
        errcnt += 1
        print(f"{WARN} got empty stdout while listing network hardware")
    if errcnt != 0:
        return {}

    lines = out.strip().splitlines()
    pci_lgnm_kv = {}
    pci_addr = ''
    lgc_name = ''
    for line in lines:
        line = line.strip()
        if 'bus info:' in line and 'pci@' in line:
            try:
                pci_addr = line.split('pci@')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract bus info from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting bus info")
        if not pci_addr:
            continue
        if 'logical name:' in line:
            try:
                lgc_name = line.split('logical name:')[-1].strip()
            except BaseException as e:
                log.debug("Tried to extract logical name from %s but hit "
                          "exception: %s", line, e)
                print(f"{WARN} hit exception while extracting logical name")
        if pci_addr and lgc_name:
            pci_lgnm_kv[pci_addr] = lgc_name

    log.debug("Got pci_lgnm_kv: %s", pci_lgnm_kv)
    if not pci_lgnm_kv:
        print(f"{ERROR} cannot map network PCI address to logical name")
    return pci_lgnm_kv


def map_network_devicename_to_logicalname(
        pci_nic_kv: Dict,
        pci_lgnm_kv: Dict) -> Dict[str, str]:
    """Map network device name to its logical name.
    Args:
        pci_nic_kv: {pciAddress: networkDeviceName, ...}
        pci_lgnm_kv: {pciAddress: logicalName, ...}
    Returns:
        {networkDeviceName: logicalName, ...} if succeeded. Else, {}.
    """
    errcnt = 0
    if not pci_nic_kv or isinstance(pci_nic_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_nic_kv: {pci_nic_kv}")
    if not pci_lgnm_kv or isinstance(pci_lgnm_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_lgnm_kv: {pci_lgnm_kv}")
    if errcnt != 0:
        return {}

    nic_lgnm_kv = {}
    for key, val in pci_nic_kv.items():
        # Re-set colon_split_scsi_len to 0 for each iteration
        pci_addr = key
        pci_seg_len = 0
        try:
            pci_seg_len = len(key.split(':'))
        except BaseException as e:
            log.debug("Tried to get length of ':' split PCI address %s but hit "
                      "exception: %s", key, e)
            print(f"{WARN} hit exception while getting length of PCI address " +
                  "segment")
        if pci_seg_len < 2 or pci_seg_len > 3:
            log.debug("Invalid PCI address: %s", key)
            print(f"{WARN} get invalid PCI address: {key}")
        if pci_seg_len == 2:
            # Add 0 to lspci format to match lshw format
            pci_addr = f"0000:{key}"
        log.debug("Make up original SCSI address %s to %s", key, pci_addr)
        net_lgnm = ''
        try:
            net_lgnm = pci_lgnm_kv[pci_addr]
        except KeyError:
            log.debug("Tried to extract network logical name from %s but hit " +
                      "KeyError: %s", pci_lgnm_kv, e)
            print(f"{WARN} hit exception while extracting network logical name")
            continue
        if net_lgnm:
            nic_lgnm_kv[val] = net_lgnm
    log.debug("Got nic_lgnm_kv: %s", nic_lgnm_kv)
    if not nic_lgnm_kv:
        print(f"{ERROR} cannot map network device name to logical name")
    return nic_lgnm_kv


def get_speed_of_network_interface(netif: str) -> int:
    """Get network interface speed.
    Args:
        netif: logical name of network interface.
    Returns:
        speed in Mb/s if succeeded. Else, -1.
    """
    if not netif or isinstance(netif, str) is False:
        print(f"{ERROR} Invalid parameter netif: {netif}")
        return -1
    netif = netif.split('@')[0]
    speed_file = f"/sys/class/net/{netif}/speed"
    speed = -1
    try:
        with open(speed_file, mode="r", encoding="utf-8") as fh:
            content = fh.read()
        speed = int(content)
    except BaseException as e:
        log.debug("Tried to get speed of %s but hit exception: %s", netif, e)
        print(f"{ERROR} hit exception while extracting speed of network " +
              f"interface: {netif}")

    log.debug("Speed of %s is %d Mb/s", netif, speed)
    return speed


def get_network_logicalname_by_ip(ipaddr: str, lgnm_ip_kv: Dict) -> str:
    """Get network logical name of input IP address.
    Args:
        ipaddr: IP address string.
    Returns:
        network device logical name which is set with given IP address if
        succeeded. Else, ''.
    """
    errcnt = 0
    if not ipaddr or isinstance(ipaddr, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter ipaddr: {ipaddr}")
        return ''
    if not lgnm_ip_kv or isinstance(lgnm_ip_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter lgnm_ip_kv: {lgnm_ip_kv}")
    if errcnt != 0:
        return ''

    net_lgnm = ''
    found_cnt = 0
    for key, val in lgnm_ip_kv.items():
        if ipaddr == val:
            found_cnt += 1
            net_lgnm = key
            log.debug("%s is set to %s", ipaddr, val)
            print(f"{INFO} has IP address {ipaddr} set to network interface: " +
                  f"{key}")

    if found_cnt == 0:
        print(f"{ERROR} IP address {ipaddr} is not set to any active network " +
              "interface")
    if found_cnt > 1:
        net_lgnm = ''
        print(f"{ERROR} IP address {ipaddr} was set to {found_cnt} network " +
              "interfaces")
        print(f"{ERROR} sets the network interface to ''")

    return net_lgnm


def check_network_device(
        pci_kv: Dict,
        supp_nic_kv: Dict,
        focused_netif: str,
        min_link_speed: int) -> Tuple[int, Dict]:
    """Check network device.
    Args:
        pci_kv: output of lspci.
        supp_nic_kv: Network Interface Card supported in NIC_adapters.json.
        focused_netif: network interface concerned.
        min_link_speed: MIN_LINK_SPEED in HW_requirements.json.
    Returns:
        (error_count, stor_kv)
    """
    errcnt = 0
    if not pci_kv or isinstance(pci_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter pci_kv: {pci_kv}")
    if not supp_nic_kv or isinstance(supp_nic_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter supp_nic_kv: {supp_nic_kv}")
    if not focused_netif or isinstance(focused_netif, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter focused_netif: {focused_netif}")
    if isinstance(min_link_speed, int) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter min_link_speed: {min_link_speed}")
    if errcnt != 0:
        print(f"{ERROR} cannot check network device")
        return {}

    nic_error = True
    net_lgnms = []
    ok_net_ctrlrs = []
    speed_error = True
    marked_pci_nic_kv = mark_network_devicename(pci_kv, supp_nic_kv)
    if not marked_pci_nic_kv:
        errcnt += 1
        nic_error = True
    else:
        marked_nics = list(marked_pci_nic_kv.values())
        for mk_nic in marked_nics:
            if '[OK]' in mk_nic:
                net_ctrlr_name = mk_nic.replace(' [OK]', '')
                ok_net_ctrlrs.append(net_ctrlr_name)

    pci_lgnm_kv = map_network_pci_to_logicalname()
    if not pci_lgnm_kv:
        errcnt += 1
        nic_error = True
    if marked_pci_nic_kv and pci_lgnm_kv:
        nic_lgnm_kv = map_network_devicename_to_logicalname(
                          marked_pci_nic_kv,
                          pci_lgnm_kv)
        if not nic_lgnm_kv:
            errcnt += 1
            nic_error = True
        else:
            net_lgnms = list(nic_lgnm_kv.values())

    if not net_lgnms:
        errcnt += 1
        nic_error = True
    else:
        nic_error = False

    netif_speed = get_speed_of_network_interface(focused_netif)
    if netif_speed < 0:
        print(f"{ERROR} has network interface: {focused_netif}. But its " +
              "speed is unknown")
        errcnt += 1
        speed_error = True
    elif netif_speed >= min_link_speed:
        speed_error = False
        print(f"{INFO} has {focused_netif} with speed {netif_speed} Mb/s. " +
              f"It complies with ECE required {min_link_speed} Mb/s")
    else:
        errcnt += 1
        speed_error = True
        print(f"{ERROR} has {focused_netif} with speed {netif_speed} Mb/s. " +
              f"It is less than ECE required {min_link_speed} Mb/s")

    net_kv = {}
    net_kv['network_controller_error'] = nic_error
    net_kv['network_controllers'] = ok_net_ctrlrs
    net_kv['network_interfaces'] = net_lgnms
    net_kv['netdev_with_IP'] = focused_netif
    net_kv['netdev_speed_error'] = speed_error
    net_kv['network_interface_speed'] = netif_speed
    net_kv['net_errcnt'] = errcnt

    log.debug("Generated net_kv: %s", net_kv)
    return net_kv


def check_tuned_profile() -> int:
    """Check tuned profile.
    Args:
    Returns:
        0 if tuned profile is OK.
        1 if tuned profile is not OK.
        exit directly if hit exception.
    """
    print(f"{INFO} is checking tuned profile")
    # is tuned active?
    isact_cmd = 'systemctl is-active tuned'
    i_out, i_err, i_rc = runcmd(isact_cmd, True)
    if i_rc != 0:
        hopeless = False
        log.debug("Ran: %s. Got return code: %d", isact_cmd, i_rc)
        if i_out.strip() and 'inactive' in i_out:
            print(f"{WARN} the system daemon 'tuned' needs to be started")
        else:
            hopeless = True
            print(f"{ERROR} hit error while checking active state of the " +
                  "'tuned' daemon")
        if i_err.strip():
            log.debug("Ran: %s. Got error: %s", isact_cmd, i_err)
        if hopeless is True:
            return 1
    if i_rc == 0 and not i_out.strip():
        log.debug("Ran: %s. Got emtpy stdout", isact_cmd)
        print(f"{ERROR} got nothing while querying active state of the " +
              "'tuned' daemon")
        return 1

    # restart tuned to apply current profile.
    rest_cmd = 'systemctl restart tuned'
    _, r_err, r_rc = runcmd(rest_cmd, True)
    if r_rc != 0:
        log.debug("Ran: %s. Got return code: %d", rest_cmd, r_rc)
        print(f"{ERROR} hit error while restarting the 'tuned' daemon")
        if r_err.strip():
            log.debug("Ran: %s. Got error: %s", rest_cmd, r_err)
        return 1
    else:
        log.debug("Tuned has been restarted by cmd: %s", rest_cmd)

    # check current active profile.
    taa_cmd = 'tuned-adm active'
    a_out, a_err, a_rc = runcmd(taa_cmd, True)
    if a_rc != 0:
        log.debug("Ran: %s. Got return code: %d", taa_cmd, a_rc)
        print(f"{ERROR} hit error while showing current active profile of " +
              "tuned")
        if a_err.strip():
            log.debug("Ran: %s. Got error: %s", taa_cmd, a_err)
        return 1
    if a_rc == 0 and not a_out.strip():
        log.debug("Ran: %s. Got empty stdout", taa_cmd)
        print(f"{ERROR} got nothing while showing current active profile of " +
              "tuned")
        return 1

    matched = False
    for tuned in COMPATIBLE_TUNEDS:
        tuned_str = f"Current active profile: {tuned}"
        if tuned_str in a_out:
            matched = True
            print(f"{INFO} has {a_out.strip()}")
            break
    if matched is False:
        curr_profile = ''
        try:
            curr_profile = a_out.split()[-1].strip()
        except BaseException as e:
            log.debug("Tried to extract active profile but hit exception: %s",
                      e)
            print(f"{ERROR} hit exception while extracting current active " +
                  "profile of tuned")
            return 1
        if curr_profile:
            print(f"{ERROR} has incorrect active tuned profile: {curr_profile}")
        else:
            print(f"{ERROR} has incorrect unknown active tuned profile")
        print(f"{ERROR} Please refer to {TUNED_TOOL} to reset it")
        return 1

    # matched is True
    tav_cmd = 'tuned-adm verify'
    v_out, v_err, v_rc = runcmd(tav_cmd, True)
    if v_rc != 0:
        log.debug("Ran: %s. Got return code: %d", tav_cmd, v_rc)
        print(f"{ERROR} hit error while verifying tuned profile")
        if v_err.strip():
            log.debug("Ran: %s. Got error: %s", tav_cmd, v_err)
        return 1
    if v_rc == 0 and not v_out.strip():
        log.debug("Ran: %s. Got empty stdout", tav_cmd)
        print(f"{ERROR} got nothing while verifying tuned profile")
        return 1

    log.debug("Ran: %s. Got stdout: %s", tav_cmd, v_out)
    v_out = v_out.strip()
    if 'succeeded' in v_out and 'match' in v_out:
        print(f"{INFO} current system settings match the preset profile")
        return 0
    else:
        print(f"{ERROR} current system settings do NOT match the preset " +
              "profile")
        return 1


def check_py3_yaml() -> int:
    """Check if Python3 YAML module installed.
    Args:
    Returns:
        0 if Python3 yaml cound be used. Else, 1.
    Comments:
        YAML is not needed for this tool but Scale 5.1.0+ requires.
    """
    cmd = "python3 -c '''import yaml'''"
    print(f"{INFO} is checking Python3 YAML")
    try:
        out, err, rc = runcmd(cmd)
    except BaseException as e:
        log.debug("Ran: %s. Hit exception: %s", cmd, e)
        print(f"{ERROR} hit exception while importing yaml module")
        print(f"{ERROR} Python3 YAML module is required by ECE")
        return 1
    if rc != 0:
        log.debug("Ran: %s. Got return code: %d", cmd, rc)
        print(f"{ERROR} hit error while importing Python3 YAML module")
        if err.strip():
            log.debug("Ran: %s. Got error: %s", cmd, err)
        print(f"{ERROR} Python3 YAML module is required by ECE")
        return 1
    if rc == 0:
        if out.strip():
            log.debug("Ran: %s. Got stdout: %s", cmd, out)
        print(f"{INFO} has Python3 YAML module installed")
        return 0


def summarize_check_result(
        fatal_err_cnt: int,
        result_file: str,
        start_time: str,
        end_time: str,
        dist_name: str,
        proc_name: str,
        socket_num: int,
        core_dists: List,
        ttl_mem_size_gib: int,
        dimm_slot_num: int,
        ppl_dimm_slot_num: int,
        vac_dimm_slot_num: int,
        scsi_ctrlrs: List,
        hdd_num: int,
        ssd_num: int,
        nvme_num: int,
        net_ctrlrs: List,
        netdev_speed: int,
        enable_all_ckecks: bool,
        check_stor: bool,
        check_sata: bool) -> None:
    """Install-toolkit will not print summary.
    Args:
        omitting.
    Returns:
    """
    print('')
    print("\tSummary of this standalone instance:")
    print(f"\t\tStarted at {start_time}")
    print(f"\t\tOS Readiness version {MODULE_VER}")
    print(f"\t\tHostname: {HOSTNAME}")
    print(f"\t\tOS: {dist_name}")
    print(f"\t\tProcessor architecture: {proc_name}")
    print(f"\t\tCPU sockets: {socket_num}")
    print(f"\t\tCPU cores per socket: {core_dists}")
    print(f"\t\tMemory size in total: {ttl_mem_size_gib} GiBytes")
    print(f"\t\tDIMM slots in total: {dimm_slot_num}")
    print(f"\t\tDIMM slots in use:   {ppl_dimm_slot_num}")
    print(f"\t\tDIMM slots unused:   {vac_dimm_slot_num}")
    scsi_ctrlr_num = len(scsi_ctrlrs)
    if scsi_ctrlr_num == 0:
        print("\t\tSCSI controller:\n\t\t    No supported SCSI controller ")
    if scsi_ctrlr_num == 1:
        print(f"\t\tSCSI controller:\n\t\t    {scsi_ctrlrs[0]}")
    elif scsi_ctrlr_num > 1:
        print(f"\t\tSCSI controllers:\n\t\t    {scsi_ctrlrs[0]}")
        for i in range(1, scsi_ctrlr_num):
            print(f"\t\t    {scsi_ctrlrs[i]}")
    print(f"\t\tJBOD SAS HDD device: {hdd_num}")
    print(f"\t\tJBOD SAS SSD device: {ssd_num}")
    print(f"\t\tNVMe drive:          {nvme_num}")
    nic_num = len(net_ctrlrs)
    if nic_num == 0:
        print("\t\tNetwork controller:\n\t\t    No explicitly supported " +
              "network controller")
    elif nic_num == 1:
        print(f"\t\tNetwork controller:\n\t\t    {net_ctrlrs[0]}")
    elif nic_num > 1:
        print(f"\t\tNetwork controllers:\n\t\t    {net_ctrlrs[0]}")
        for j in range(1, nic_num):
            print(f"\t\t    {net_ctrlrs[j]}")
    if netdev_speed < 0:
        print("\t\tLink speed of given IPv4: Unknown")
    else:
        print(f"\t\tLink speed of given IPv4: {netdev_speed} Mb/s")
    print(f"\t\tEnded at {end_time}")
    print('')
    print(f"{INFO} saved detailed information of this instance to " +
          f"{result_file}")

    if check_stor is True and check_sata is True:
        print(f"{WARN} has run SATA check but using SATA device for ECE is " +
              "NOT recommended")
    if enable_all_ckecks is True and fatal_err_cnt == 0:
        print(f"{INFO} can run IBM Storage Scale Erasure Code Edition\n")
    if enable_all_ckecks is False:
        print(f"{ERROR} is missing some checks. The precheck tool can NOT " +
              "claim this system could run IBM Storage Scale Erasure Code " +
              "Edition")
    if fatal_err_cnt != 0:
        print(f"{ERROR} cannot run IBM Storage Scale Erasure Code Edition\n")


def main():
    """Main entrance.
    Args:
    Returns:
        count of fatal errors that the checkings hit.
    """
    start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:23]
    global log
    enable_all_ckecks = False
    # Fatal error count
    fatal_err_cnt = 0
    final_kv = {}

    final_kv['start_time'] = start_time
    final_kv['MOR_VERSION'] = MODULE_VER

    (ip_addr, json_dir, fips, check_md5, check_cpu, check_os, check_pkg,
     check_mem, check_stor, check_net, check_tuned, check_sata, toolkit,
     isverbose) = parse_arguments()

    log_postfix = start_time.replace(' ', '_').replace('-', '_').replace(':',
                      '_')
    rltv_fn = os.path.basename(__file__).rsplit('.', 1)[0]
    log_file = f"{rltv_fn}_debug_{log_postfix}.out"
    log = set_logger(json_dir, log_file, isverbose)

    ipok = is_ipv4(ip_addr)
    if ipok is False:
        fatal_err_cnt += 1
        print('')
        return fatal_err_cnt

    lgnm_ip_kv = map_active_netif_to_ip()
    if not lgnm_ip_kv:
        fatal_err_cnt += 1
        print(f"{ERROR} {ip_addr} is not available on active network device\n")
        return fatal_err_cnt
    else:
        active_ips = list(lgnm_ip_kv.values())
        if ip_addr not in active_ips:
            fatal_err_cnt += 1
            print(f"{ERROR} suggests choosing IP address from {active_ips}\n")
            return fatal_err_cnt

    if check_md5 is True and check_cpu is True and check_os is True and \
       check_pkg is True and check_mem is True and check_stor is True and \
       check_net is True and check_tuned is True:
        enable_all_ckecks = True
        log.debug("All tests are enabled")
    else:
        enable_all_ckecks = False
        fatal_err_cnt += 1
    log.debug("Are all tests enabled? %s", enable_all_ckecks)

    # JSON loads and calculate and store MD5
    supp_os_fp = os.path.join(json_dir, 'supported_OS.json')
    supp_pkg_fp = os.path.join(json_dir, 'packages.json')
    supp_scsi_ctrlr_fp = os.path.join(json_dir, 'SAS_adapters.json')
    supp_nic_fp = os.path.join(json_dir, 'NIC_adapters.json')
    requ_param_fp = os.path.join(json_dir, 'HW_requirements.json')

    supp_os_kv = load_json(supp_os_fp)
    supp_pkg_kv = load_json(supp_pkg_fp)
    supp_scsi_ctrlr_kv = load_json(supp_scsi_ctrlr_fp)
    supp_nic_kv = load_json(supp_nic_fp)
    requ_param_kv = load_json(requ_param_fp)

    json_ver_errcnt, json_ver_kv = get_json_versions(
                                       supp_os_kv,
                                       supp_pkg_kv,
                                       supp_scsi_ctrlr_kv,
                                       supp_nic_kv,
                                       requ_param_kv)
    fatal_err_cnt += json_ver_errcnt
    log.debug("Show header of the output")
    show_header(MODULE_VER, toolkit, json_ver_kv)
    log.debug("Ended showing header")

    # Force check
    isroot = check_root_user()
    if isroot is False:
        fatal_err_cnt += 1

    supp_os_md5 = ''
    supp_pkg_md5 = ''
    supp_sas_md5 = ''
    supp_nic_md5 = ''
    requ_param_md5 = ''
    if fips is True:
        log.debug("FIPS mode enabled")
        print(f"{ERROR} is running checks with FIPS mode")
        fatal_err_cnt += 1
        check_md5 = False
        supp_os_md5 = "FIPS"
        supp_pkg_md5 = "FIPS"
        supp_sas_md5 = "FIPS"
        supp_nic_md5 = "FIPS"
        requ_param_md5 = "FIPS"
    else:
        log.debug("Calculate MD5 checksums")
        supp_os_md5 = get_md5_cksum(supp_os_fp)
        supp_pkg_md5 = get_md5_cksum(supp_pkg_fp)
        supp_sas_md5 = get_md5_cksum(supp_scsi_ctrlr_fp)
        supp_nic_md5 = get_md5_cksum(supp_nic_fp)
        requ_param_md5 = get_md5_cksum(requ_param_fp)
        if supp_os_md5 == 'Unknown':
            fatal_err_cnt += 1
        if supp_pkg_md5 == 'Unknown':
            fatal_err_cnt += 1
        if supp_sas_md5 == 'Unknown':
            fatal_err_cnt += 1
        if supp_nic_md5 == 'Unknown':
            fatal_err_cnt += 1
        if requ_param_md5 == 'Unknown':
            fatal_err_cnt += 1

    md5_to_check_kv = {
        'supported_OS.json': supp_os_md5,
        'packages.json': supp_pkg_md5,
        'SAS_adapters.json': supp_sas_md5,
        'NIC_adapters.json': supp_nic_md5,
        'HW_requirements.json': requ_param_md5
    }

    final_kv['json_file_md5'] = md5_to_check_kv

    if check_md5 is True:
        (cksum_errcnt,
         md5_stat_kv) = verify_file_checksum(md5_to_check_kv)
        fatal_err_cnt += cksum_errcnt
        final_kv['md5_checking_state'] = md5_stat_kv
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped json file MD5 checksum checking")
        final_kv['md5_checking_state'] = 'Unknown'

    log.debug("Set required parameters to variables")
    min_socket = 0
    min_cores = 0
    min_gb_ram = 0
    max_dev_num = 0
    min_link_speed = 0
    min_loghome_size = 0
    try:
        min_socket = int(requ_param_kv['MIN_SOCKET'])
        min_cores = int(requ_param_kv['MIN_CORES'])
        min_gb_ram = int(requ_param_kv['MIN_GB_RAM'])
        max_dev_num = int(requ_param_kv['MAX_DRIVES'])
        min_link_speed = int(requ_param_kv['MIN_LINK_SPEED'])
        min_loghome_size = int(requ_param_kv['MIN_LOGHOME_DRIVE_SIZE'])
    except KeyError as e:
        fatal_err_cnt += 1
        log.debug("Tried to extract required parameters but hit KeyError: %s",
                  e)
        print(f"{ERROR} hit exception while extracting required parameters\n")
        return fatal_err_cnt

    log.debug("Set min_socket: %d, min_cores: %d, min_gb_ram: %d, max_dev_num: "
              "%d, min_link_speed: %d, min_loghome_size: %d", min_socket,
              min_cores, min_gb_ram, max_dev_num, min_link_speed,
              min_loghome_size)

    final_kv['parameters'] = {
        'local_hostname': HOSTNAME,
        'IP_address': ip_addr,
        'json_file_location': json_dir,
        'check_md5': check_md5,
        'check_CPU': check_cpu,
        'check_OS': check_os,
        'check_package': check_pkg,
        'check_memory': check_mem,
        'check_storage': check_stor,
        'check_network': check_net,
        'minimum_CPU_socket_number_required': min_socket,
        'minimum_CPU_core_number_required': min_cores,
        'minimum_RAM_in_GiB_required': min_gb_ram,
        'maximum_storage_device_number_required': max_dev_num,
        'minimum_network_link_speed_required': min_link_speed
    }

    virt_type = detect_virtualization()
    if virt_type not in ['vmware', 'none']:
        fatal_err_cnt += 1
    # Check cpu
    proc_name = 'Unknown'
    sock_num = 0
    # core distribution
    core_dists = []
    if check_cpu is True:
        proc_name = check_processor()
        if proc_name != 'x86_64' and proc_name != 'aarch64':
            fatal_err_cnt += 1
        cpu_err = True
        if virt_type == 'vmware':
            cpu_err, sock_num, core_dists = check_cpu_by_lscpu(
                                                True,
                                                min_socket,
                                                min_cores)
        else:
            cpu_err, sock_num, core_dists = check_cpu_by_dmidecode(
                                                min_socket,
                                                min_cores)
        final_kv['processor_name'] = proc_name
        final_kv['CPU_socket_num'] = sock_num
        final_kv['CPU_cores_per_socket'] = core_dists
        final_kv['CPU_error'] = cpu_err
        if cpu_err is True:
            fatal_err_cnt += 1
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped CPU checking")

    # Check linux_distribution
    os_name = 'Unknown'
    if check_os:
        os_error, os_name = check_os_distribution(supp_os_kv)
        final_kv['OS'] = os_name
        if os_error is True:
            fatal_err_cnt += 1
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped OS checking")

    # Check package
    pkg_ins_kv = {}
    if check_pkg is True:
        pkg_errcnt, pkg_ins_kv = check_package(supp_pkg_kv)
        fatal_err_cnt += pkg_errcnt
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped package checking")
    final_kv['package_installation_state'] = pkg_ins_kv

    # Get node serial number. Force check
    ss_error = False
    ser_num = get_system_serial_number()
    if ser_num == '00000000':
        ss_error = True
    final_kv['system_serial_error'] = ss_error
    final_kv['system_serial_number'] = ser_num

    # Check memory
    ttl_mem_size_gib = 0
    dimm_slot_num = 0
    ppl_dimm_slot_num = 0
    vac_dimm_slot_num = 0
    if check_mem is True:
        mem_err = False
        mem_kv = check_memory(min_gb_ram)
        if mem_kv:
            final_kv.update(mem_kv)
            try:
                mem_err = mem_kv['memory_error']
                ttl_mem_size_gib = int(mem_kv['memory_size'])
                dimm_slot_num = int(mem_kv['total_dimm_slot_num'])
                ppl_dimm_slot_num = int(mem_kv['populated_dimm_slot_num'])
                vac_dimm_slot_num = int(mem_kv['vacant_dimm_slot_num'])
            except KeyError as e:
                fatal_err_cnt += 1
                log.debug("Tried to extract items from memory KV pairs but hit "
                          "KeyError: %s", e)
                print(f"{ERROR} hit exception while extracting memory info")
        else:
            mem_err = True
            print(f"{ERROR} cannot get memory device info")
        if mem_err is True:
            fatal_err_cnt += 1
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped memory checking")

    # Force check
    pci_kv = list_pci_device()
    if not pci_kv:
        fatal_err_cnt += 1

    scsi_ctrlrs = []
    num_of_hdd = 0
    num_of_ssd = 0
    num_of_nvme = 0
    if check_stor is True:
        if check_sata is True:
            log.debug("SATA device check is enabled")
            print(f"{WARN} enables SATA check. However, it is not " +
                  "recommended to use SATA device for ECE")
        else:
            log.debug("SATA device check is not enabled")
        stor_kv = {}
        if virt_type == 'vmware':
            stor_kv = check_vmware_storage(
                          pci_kv,
                          supp_scsi_ctrlr_kv,
                          min_loghome_size,
                          max_dev_num,
                          check_pkg,
                          check_sata)
        else:
            stor_kv = check_physical_storage(
                          pci_kv,
                          supp_scsi_ctrlr_kv,
                          min_loghome_size,
                          max_dev_num,
                          check_pkg,
                          check_sata)
        if stor_kv:
            final_kv.update(stor_kv)
            stor_errcnt = 0
            try:
                scsi_ctrlrs = stor_kv['SCSI_controllers']
                num_of_hdd = int(stor_kv['HDD_device_number'])
                num_of_ssd = int(stor_kv['SSD_device_number'])
                num_of_nvme = int(stor_kv['NVMe_drive_number'])
                stor_errcnt = int(stor_kv['storage_errcnt'])
            except KeyError as e:
                fatal_err_cnt += 1
                log.debug("Tried to extract items from storage device KV pair "
                          "but hit KeyError: %s", e)
                print(f"{ERROR} hit exception while extracting storage " +
                      "device info")
            fatal_err_cnt += stor_errcnt
        else:
            fatal_err_cnt += 1
            print(f"{ERROR} got no storage device info")
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped storage checking")

    # Network checks
    final_kv['local_hostname'] = HOSTNAME
    final_kv['IP_address_is_possible'] = True
    final_kv['ip_address'] = ip_addr
    net_ctrlrs: List[str] = []
    netdev_speed: int = -1
    if check_net is True:
        log.debug("Check network device")
        # Check if input IP is a local IP
        ip_to_netif = get_network_logicalname_by_ip(ip_addr, lgnm_ip_kv)
        if not ip_to_netif:
            fatal_err_cnt += 1
            print('')
            return fatal_err_cnt
        net_kv = check_network_device(pci_kv, supp_nic_kv, ip_to_netif,
                     min_link_speed)
        if net_kv:
            final_kv.update(net_kv)
            net_errcnt = 0
            try:
                net_ctrlrs = net_kv['network_controllers']
                netdev_speed = int(net_kv['network_interface_speed'])
                net_errcnt = int(net_kv['net_errcnt'])
            except KeyError as e:
                log.debug("Tried to extract items from network device KV pair "
                          "but hit KeyError: %s", e)
                print(f"{ERROR} hit exception while extracting network " +
                      "device info")
            fatal_err_cnt += net_errcnt
        else:
            fatal_err_cnt += 1
            print(f"{ERROR} got no network device info")
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped network checking")

    # Check tuned
    if check_tuned is True:
        tuned_err = False
        rc = check_tuned_profile()
        if rc != 0:
            tuned_err = True
        final_kv['tuned_fail'] = tuned_err
        if tuned_err is True:
            fatal_err_cnt += 1
    else:
        fatal_err_cnt += 1
        print(f"{ERROR} has skipped tuned checking")

    # Check py3 YAML. Force check
    yaml_err = False
    yaml_rc = check_py3_yaml()
    if yaml_rc != 0:
        yaml_err = True
    final_kv['py3_yaml_fail'] = yaml_err
    if yaml_err is True:
        fatal_err_cnt += 1

    # Set general status of acceptance of this node
    os_ready = False
    if fatal_err_cnt == 0 and enable_all_ckecks is True:
        os_ready = True
        log.debug("All checks were enabled and passed")
    else:
        os_ready = False
    log.debug("Are all checks enabled? %s. Hit %d fatal errors",
              enable_all_ckecks, fatal_err_cnt)
    final_kv['ECE_node_ready'] = os_ready

    result_fn = f"{ip_addr}.json"
    result_file = os.path.join(json_dir, result_fn)

    end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:23]
    final_kv['end_time'] = end_time

    try:
        outputdata = json.dumps(final_kv, indent=4)
        with open(result_file, mode="w", encoding="utf-8") as fh:
            fh.write(outputdata)
    except BaseException as e:
        fatal_err_cnt += 1
        log.debug("Tried to write %s but hit exception: %s", result_file, e)
        print(f"{ERROR} hit exception while writing file {result_file}")

    log.debug("Got toolkit: %s, fatal_err_cnt: %s", toolkit, fatal_err_cnt)
    if toolkit is True and fatal_err_cnt > 0:
        print(f"{ERROR} does not have any supported configuration to run ECE")
    if toolkit is False:
        summarize_check_result(fatal_err_cnt, result_file, start_time, end_time,
            os_name, proc_name, sock_num, core_dists, ttl_mem_size_gib,
            dimm_slot_num, ppl_dimm_slot_num, vac_dimm_slot_num, scsi_ctrlrs,
            num_of_hdd, num_of_ssd, num_of_nvme, net_ctrlrs, netdev_speed,
            enable_all_ckecks, check_stor, check_sata)

    return fatal_err_cnt


if __name__ == '__main__':
    sys.exit(main())
