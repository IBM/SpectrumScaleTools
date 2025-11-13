"""
This module can perform fping and nsdperf tests against a set of hosts' network.
It compares the test results with Key Performance Indicators (KPI) then
determines if the network of the hosts is ready for Storage Scale ECE.
"""

import json
import os
import sys
import socket
import datetime
import platform
import shlex
import time
from subprocess import Popen, PIPE, call, STDOUT
from shutil import copyfile
from collections import OrderedDict
import argparse
import operator
from math import sqrt, ceil
from functools import reduce
import re
import csv
import shutil

# This script version, independent from the JSON versions
VERSION = "1.30"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
PURPLE = '\033[35m'
GOLDEN = '\033[33m'
BOLDRED = '\033[91;1m'
BOLDGOLDEN = '\033[33;1m'
RESETCOL = '\033[0m'

INFO = "[ {0}INFO{1}  ] ".format(GREEN, RESETCOL)
WARN = "[ {0}WARN{1}  ] ".format(YELLOW, RESETCOL)
ERRO = "[ {0}FATAL{1} ] ".format(RED, RESETCOL)
QUIT = "[ {0}QUIT{1}  ] ".format(RED, RESETCOL)

# KPI and acceptance values
KPI_AVG_LATENCY = 1.00 # 1 msec or less
KPI_MAX_LATENCY = 2.00
KPI_STDDEV_LAT = float("{:.2f}".format(KPI_AVG_LATENCY / 3.0))
KPI_NSD_THROUGH = 2000 # 2000 MB/s or more, with lots of margin
KPI_DIFF_PCT = 20.0
ACC_FPING_COUNT = 500 # 500 or more
ACC_TESTER_THRE = 32 # fixed 32
ACC_BUFFSIZE = 2 * 1024 * 1024 # fixed 2M
ACC_TTIME = 1200 # 1200 or more

# TODO Move following global variables to json file
MIN_HOST_NUM = 2
MAX_HOST_NUM = 64
# Minimum fping count
MIN_FPING_COUNT = 2
# Tester threads form nsdperf
MAX_TESTERS = 4096
# Parallel connection from maxTcpConnsPerNodeConn
DEF_PARALLEL = 2
# Max parallel connection from nsdperf
MAX_PARALLEL = 8192 - 1
# Socket size from nsdperf
MAX_SOCKSIZE = 100 * 1024 * 1024
# Buffer size from nsdperf
MIN_BUFFSIZE = 4 * 1024
MAX_BUFFSIZE = 16 * 1024 * 1024

# GITHUB URL
GIT_URL = "https://github.com/IBM/SpectrumScaleTools"

NSDTOOL = "nsdperfTool.py"
DEPE_PKG = "packages.json"
HOST_FL = "hosts.json"

# IP RE
IPPATT = re.compile('.*inet\s+(?P<ip>.*)\/\d+')

PYTHON2 = False
try:
    input = raw_input
    PYTHON2 = True
except NameError:
    PYTHON2 = False

if PYTHON2 is False:
    import statistics


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
            if not dict_obj:
                print("{0}Tried to load JSON file {1} but got ".format(ERRO,
                      json_file) + "nothing")
                return None
            return dict_obj
    except Exception as e:
        print("{0}Tried to load JSON file {1} but hit ".format(ERRO,
              json_file) + "exception: {}".format(e))
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


def check_localhost_is_in_hosts(hosts):
    """
    Params:
        hosts: hostname list.
    Returns:
        0 if localhost is in hosts.
        exit if hit error or localhost was not in hosts.
    """
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    localNode = None
    try:
        raw_out = os.popen("ip addr show").read()
    except BaseException as e:
        print("{}Tried to get IP addresses of localhost ".format(ERRO) +
              "but hit exception: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))

    ips = IPPATT.findall(raw_out)

    # check for match with one of input ip addresses
    if any(i for i in hosts if i in ips) is False:
        print("{0}localhost is not in hosts: {1}".format(ERRO, hosts))
        sys.exit("{}Bye!\n".format(QUIT))
    else:
        return 0


def estimate_runtime(
        hosts,
        fp_count,
        ttime_per_inst):
    """
    Params:
        hosts: hostname list.
        fp_count: count of fping packet.
        ttime_per_inst: test time perf nsdperf instance.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: hosts".format(ERRO))
    if not fp_count or isinstance(fp_count, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: fp_count".format(ERRO))
    if not ttime_per_inst or isinstance(ttime_per_inst, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: ttime_per_inst".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    host_num = len(hosts)
    fping_rt = host_num * fp_count
    # add 20 extra seconds per nsdperf instance for overhead(compile,
    # startup, shutdown, etc.)
    o2m_nsdperf_rt = host_num * (ttime_per_inst + 20)
    m2m_nsdperf_rt = ttime_per_inst + 20

    estimated_rt = fping_rt + o2m_nsdperf_rt + m2m_nsdperf_rt
    runtime_in_m = int(estimated_rt / 60.0)

    print("{}The total time consumption of running ".format(INFO) +
          "this network readiness instance is estimated to take " +
          "at least {0}{1} minutes{2}".format(PURPLE, runtime_in_m,
          RESETCOL))
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--hosts',
        action='store',
        dest='hosts',
        help='IPv4 addresses in CSV format. E.g., IP0,IP1,...',
        metavar='CSV_IPV4',
        type=str,
        default="")
    parser.add_argument(
        '-s',
        '--save-hosts',
        action='store_true',
        dest='save_hosts',
        help='[Over]write {} with IP addresses '.format(HOST_FL) +
        'followed --hosts',
        default=False)
    parser.add_argument(
        '-c',
        '--fping-count',
        action='store',
        dest='fping_count',
        help='count of fping packets to send to each target. The ' +
        'minimum value can be set to {} packets for quick '.format(
        MIN_FPING_COUNT) + 'test. For certification, it is at ' +
        'least {} '.format(ACC_FPING_COUNT) + 'packets',
        metavar='COUNT',
        type=int,
        default=500)
    parser.add_argument(
        '-t',
        '--test-time',
        action='store',
        dest='ttime_per_inst',
        help='test time per nsdperf instance in sec. The minimum ' +
        'value can be set to 10 sec for quick test. For ' +
        'certification, it is at least {} sec'.format(ACC_TTIME),
        metavar='TIME',
        type=int,
        default=ACC_TTIME)
    parser.add_argument(
        '-r',
        '--thread-number',
        action='store',
        dest='test_thread',
        help='test thread number per nsdperf instance on client. ' +
        'The minimum value is 1 and the maximum value is ' +
        '{0}. For certification, it is {1}'.format(MAX_TESTERS,
        ACC_TESTER_THRE),
        metavar='THREAD',
        type=int,
        default=ACC_TESTER_THRE)
    parser.add_argument(
        '-p',
        '--parallel',
        action='store',
        dest='para_conn',
        help='parallel socket connections of nsdperf per ' +
        'instance. The minimum value is 1 and the maximum value ' +
        'is {0}. Default value is {1}'.format(MAX_PARALLEL,
        DEF_PARALLEL),
        metavar='PARALLEL',
        type=int,
        default=DEF_PARALLEL)
    parser.add_argument(
        '-b',
        '--buffer-size',
        action='store',
        dest='buff_size',
        help='buffer size for each I/O of nsdperf in byte ' +
        'The minimum value is {} bytes '.format(MIN_BUFFSIZE) +
        'and the maximum value is {} bytes. '.format(MAX_BUFFSIZE) +
        'For certification, it is {} bytes'.format(ACC_BUFFSIZE),
        metavar='BUFFSIZE',
        type=int,
        default=ACC_BUFFSIZE)
    parser.add_argument(
        '-o',
        '--socket-size',
        action='store',
        dest='socket_size',
        help='maximum socket send and receive buffer size in ' +
        'byte. 0 means the system default setting. The maximum ' +
        'value is {} bytes. This tool '.format(MAX_SOCKSIZE) +
        'implicitly sets the socket size to the I/O buffer size ' +
        'if socket size was not specified',
        metavar='SOCKSIZE',
        type=int,
        default=ACC_BUFFSIZE)
    parser.add_argument(
        '--rdma',
        action='store',
        dest='rdma',
        help='assign ports in CSV format. E.g., ib0,ib1,... ' +
        'Use logical device name rather than mlx name',
        metavar='PORTS_CSV',
        default="")
    parser.add_argument(
        '--no-package-check',
        action='store_true',
        dest='no_rpm_check',
        help='disable dependent package check',
        default=False)

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='Network Readiness {}\n'.format(VERSION))

    args = parser.parse_args()

    err_cnt = 0
    if args.fping_count < 2:
        err_cnt += 1
        print("{}fping count cannot be less than 2".format(ERRO))
    if args.ttime_per_inst < 10:
        err_cnt += 1
        print("{}nsdperf test time cannot be less ".format(ERRO) +
              "than 10 sec")
    if args.test_thread < 1 or args.test_thread > MAX_TESTERS:
        err_cnt += 1
        print("{}nsdperf test threads are out of range".format(ERRO))
    if args.para_conn < 1 or args.para_conn > MAX_PARALLEL:
        err_cnt += 1
        print("{}nsdperf parallel connection is out ".format(ERRO) +
              "of range")
    if args.buff_size < MIN_BUFFSIZE or args.buff_size > MAX_BUFFSIZE:
        err_cnt += 1
        print("{}nsdperf buffer size is out of range".format(ERRO))
    if args.socket_size < 0 or args.socket_size > MAX_SOCKSIZE:
        err_cnt += 1
        print("{}nsdperf socket size is out of range".format(ERRO))
    if 'mlx' in args.rdma:
        err_cnt += 1
        print("{}RDMA ports must be OS name such as ".format(ERRO) +
              "ib0 or ib0,ib1,...")
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))
    # we check is a CSV string and if so we put it on dictionary
    is_hosts_input = False
    host_kv = {}
    if args.hosts:
        raw_hosts = args.hosts
        hosts = raw_hosts.split(",")
        host_num = len(hosts)
        if host_num < MIN_HOST_NUM or host_num > MAX_HOST_NUM:
            print("{0}Input host number must be between {1} ".format(
                  ERRO, MIN_HOST_NUM) + "and {}".format(MAX_HOST_NUM))
            sys.exit("{}Bye!\n".format(QUIT))
        for host in hosts:
            if ' ' in host:
                print("{}Input host is not CSV format".format(ERRO))
                sys.exit("{}Bye!\n".format(QUIT))
            host_kv.update({host: "ECE"})
        is_hosts_input = True

    if args.save_hosts is True and is_hosts_input is False:
        print("{}--save-hosts must be used together ".format(ERRO) +
              "with --hosts")
        sys.exit("{}Bye!\n".format(QUIT))

    rdma_ports = []
    rdma_test = False
    if args.rdma:
        raw_rdma_port = args.rdma
        rdma_ports = raw_rdma_port.split(",")
        for port in rdma_ports:
            if ' ' in port:
                print("{}Input RDMA port is not CSV format".format(ERRO))
                sys.exit("{}Bye!\n".format(QUIT))
        rdma_test = True

    return (args.fping_count, args.ttime_per_inst, args.test_thread,
            args.para_conn, args.buff_size, args.socket_size, is_hosts_input,
            host_kv, rdma_test, rdma_ports, args.no_rpm_check,
            args.save_hosts)


def check_parameters(
        fping_count,
        ttime_per_inst,
        thread_num,
        para_conn,
        buffer_size,
        socket_size):
    """
    Params:
        fping_count: pakcet count per fping instance.
        ttime_per_inst: test time per nsdperf instance.
        thread_num: test thread number per nsdperf instance.
        para_conn: parallel socket connection number per nsdperf instance.
        buffer_size: I/O buffer size of nsdperf.
        socket_size: socket size.
    Returns:
        True if all parameters meet the requirements.
        False if not.
    """
    acceptance_flag = False
    if fping_count and fping_count >= ACC_FPING_COUNT and \
        ttime_per_inst and ttime_per_inst >= ACC_TTIME and \
        thread_num and thread_num == ACC_TESTER_THRE and \
        thread_num >= para_conn and \
        buffer_size and buffer_size == ACC_BUFFSIZE and \
        socket_size and socket_size >= buffer_size:
        acceptance_flag = True
    return acceptance_flag


def show_header(
        module_version,
        fping_count,
        ttime_per_inst,
        thread_num,
        para_conn,
        buffer_size,
        socket_size):
    """
    Params:
        module_version:
        fping_count:
        ttime_per_inst:
        thread_num:
        para_conn:
        buffer_size:
        socket_size:
    Returns:
        0 if completed.
        exit if hit error.
    """
    print('')
    print("Welcome to Network Readiness {}".format(module_version))
    print('')
    print("The purpose of this tool is to obtain network metrics of a " +
          "list of hosts then compare them with certain KPIs")
    print("Please access to {} to get required version ".format(GIT_URL) +
          "and report issue if necessary")
    print('')
    print("{0}IMPORTANT WARNING:{1}".format(BOLDRED, RESETCOL))
    print("{}  Do NOT run this tool in production ".format(RED) +
          "environment because it would generate heavy network " +
          "traffic.".format(RESETCOL))
    print("{0}NOTE:{1}".format(BOLDGOLDEN, RESETCOL))
    print("{}  The latency and throughput numbers shown ".format(GOLDEN) +
          "are under special parameters. That is not a generic storage " +
          "standard.{}".format(RESETCOL))
    print("{}  The numbers do not reflect any ".format(GOLDEN) +
          "specification of IBM Storage Scale or any user workload " +
          "running on it.{}".format(RESETCOL))
    print('')
    if fping_count and fping_count >= ACC_FPING_COUNT:
        print("{}The fping count per instance needs at least ".format(
              INFO) + "{} request packets. Current setting ".format(
              ACC_FPING_COUNT) + "is {0} packets".format(fping_count))
    else:
        print("{}The fping count per instance needs at least ".format(
              WARN) + "{} request packets. Current setting ".format(
              ACC_FPING_COUNT) + "is {} packets".format(fping_count))
    if ttime_per_inst and ttime_per_inst >= ACC_TTIME:
        print("{0}The nsdperf needs at least {1} sec test time ".format(
              INFO, ACC_TTIME) + "per instance. Current setting is " +
              "{0} sec".format(ttime_per_inst))
    else:
        print("{0}The nsdperf needs at least {1} sec test ".format(WARN,
              ACC_TTIME) + "time per instance. Current setting is " +
              "{} sec".format(ttime_per_inst))
    if thread_num and thread_num == ACC_TESTER_THRE:
        if thread_num < para_conn:
            print("{0}{1} nsdperf test thread per instance is ".format(
                  WARN, thread_num) + "less than {} parallel ".format(
                  para_conn) + "connection(s)")
        else:
            print("{0}The nsdperf needs {1} test thread per ".format(INFO,
                  ACC_TESTER_THRE) + "instance. Current setting is " +
                  "{}".format(thread_num))
    else:
        print("{0}The nsdperf needs {1} test thread per ".format(WARN,
              ACC_TESTER_THRE) + "instance. Current setting is " +
              "{}".format(thread_num))
    if buffer_size and buffer_size == ACC_BUFFSIZE:
        if socket_size < buffer_size:
            print("{0}{1} bytes nsdperf socket size is less ".format(WARN,
                  socket_size) + "than {} bytes buffer size".format(
                  buffer_size))
        else:
            print("{0}The nsdperf needs {1} bytes buffer size. ".format(
                  INFO, ACC_BUFFSIZE) + "Current setting is " +
                  "{} bytes".format(buffer_size))
    else:
        print("{0}The nsdperf needs {1} bytes buffer size. ".format(WARN,
              ACC_BUFFSIZE) + "Current setting is {} bytes".format(
              buffer_size))
    print('')
    return 0


def run_cmd_on_host(
        host,
        cmd):
    """
    Params:
        host: hostname or IP address.
        cmd: command to be run.
    Returns:
        (stdout, stderr, rc)
    """
    if not host or isinstance(cmd, str) is False:
        return '', 'Invalid hostname or IP', 1
    if not cmd or isinstance(cmd, str) is False:
        return '', 'Invalid command', 1
    elif ';' in cmd or '&' in cmd:
        return '', "Command with ';' or '&' is not supported", 1
    ssh_cmds = [
        'ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'LogLevel=error',
        host]
    input_cmds = cmd.split()
    cmds = ssh_cmds + input_cmds
    rc = 0
    try:
        child = Popen(cmds, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = child.communicate()
        rc = child.returncode
    except BaseException as e:
        return '', "{}".format(e), 1

    if isinstance(stdout, bytes):
        stdout = stdout.decode()
    if isinstance(stderr, bytes):
        stderr = stderr.decode()
    return str(stdout), str(stderr), int(rc)


def check_firewalld_service(hosts):
    """
    Params:
        hosts: hostname list.
    Returns:
        0 if all firewallds are inactive in hosts.
        exit if hit error or firewalld was acitve in hosts.
    """
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    cmd = 'systemctl is-active firewalld'
    err_cnt = 0
    active_hosts = []
    for host in hosts:
        _, _, rc = run_cmd_on_host(host, cmd)
        # inactive, rc is 3
        if rc == 0:
            print("{0}{1} has active firewalld service".format(ERRO, host))
            active_hosts.append(host)
            err_cnt += 1
        else:
            print("{0}{1} has inactive firewalld service".format(INFO, host))
    if err_cnt > 0:
        print("{0}Stop firewalld service on hosts: {1} before ".format(ERRO,
              active_hosts) + "running this tool")
        sys.exit("{}Bye!\n".format(QUIT))


def check_tcp_port(
        hosts,
        port_num):
    """
    Params:
        hosts: hostname list.
        port_num: port number.
    Returns:
        0 if input port number is free.
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        err_cnt += 1
    if not port_num or isinstance(port_num, int) is False:
        print("{}Invalid parameter: port_num".format(ERRO))
        err_cnt += 1
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    print('')
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            openit = sock.connect_ex((host, port_num))
            print("{0}Port {1} on host {2} is free".format(INFO,
                  port_num, host))
        except BaseException as e:
            print("{0}Tried to connect {1} by {2}".format(ERRO, host,
                  port_num))
            sys.exit("{}Bye!\n".format(QUIT))
        if openit == 0:
            err_cnt += 1
            print("{0}Port {1} on host {2} is not free".format(ERRO,
                  port_num, host))
    if err_cnt > 0:
        print("{0}Not all port {1} of hosts are free".format(ERRO,
              port_num))
        sys.exit("{}Bye!\n".format(QUIT))
    return 0


def check_files_are_readable(files):
    """
    Params:
        files: filename list.
    Returns:
        0 if all files are readable.
        exit if hit error.
    """
    if not files or isinstance(files, list) is False:
        print("{}Invalid parameter: files".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    err_cnt = 0
    for fl in files:
        if os.path.isfile(fl) is False:
            err_cnt += 1
            print("{0}{1} is not a rugular file".format(ERRO, fl))
            continue
        if os.access(fl, os.R_OK) is False:
            err_cnt += 1
            print("{0}{1} does not have read permission".format(ERRO, fl))
            continue
    if err_cnt > 0:
        print("{}Not all files passed permission checking".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    return 0


def is_rpm_package_installed(
        host,
        pkg):
    """
    Params:
        host: hostname.
        pkg: package to be checked.
    Returns:
        True if RPM package is correctly installed.
        False if not.
        exit if hit certain error.
    """
    err_cnt = 0
    if not host:
        err_cnt += 1
        print("{}Invalid parameter: host".format(ERRO))
    if not pkg:
        err_cnt += 1
        print("{}Invalid parameter: pkg".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    # Determine which package manager to use
    if shutil.which("dpkg-query"):
        pkg_manager = "Ubuntu"
        pkg_cmd = "dpkg-query -W -f='${{Package}}-${{Version}}\\n' {}"
    elif shutil.which("rpm"):
        pkg_cmd = "rpm -q {}"

    if pkg == "gcc-c++":
        if pkg_manager == "Ubuntu":
            pkg = "g++"
        else:
            pkg = "gcc-c++"

    if '|' not in pkg:
        cmd = pkg_cmd.format(pkg)
        _, _, rc = run_cmd_on_host(host, cmd)
        if rc != 0:
            print("{0}{1} does not have {2} installed".format(ERRO, host, pkg))
            return False
        else:
            print("{0}{1} has {2} installed".format(INFO, host, pkg))
            return True
    else:
        subpkgs = pkg.split('|')
        found = False
        for subpkg in subpkgs:
            cmd = pkg_cmd.format(subpkg)
            _, _, rc = run_cmd_on_host(host, cmd)
            if rc == 0:
                found = True
                print("{0}{1} has {2} installed".format(INFO, host, subpkg))
        if found is False:
            pkgs = ' or '.join(subpkgs)
            print("{0}{1} does not have {2} ".format(ERRO, host, pkgs) +
                  "installed")
        return found


def check_package_on_host(
        hosts,
        pkg_kv,
        high_speed_type=''):
    """
    Params:
        hosts: hostname list.
        pkg_kv: package to be checked.
        high_speed_type: [Optional] type of high speed network.
    Returns:
        0 if package is correctly installed.
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: hosts".format(ERRO))
    if not pkg_kv or isinstance(pkg_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: host_kv".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    hs_type = ''
    if high_speed_type:
        hs_type = high_speed_type.lower()
        if hs_type != 'rdma':
            print("{}Only 'RDMA' is supported".format(ERRO))
            sys.exit("{}Bye!\n".format(QUIT))

    for host in hosts:
        out, err, rc = run_cmd_on_host(host, 'uname -r')
        out = out.strip()
        err = err.strip()
        if rc != 0 or not out:
            print("{0}{1} failed to run cmd: 'uname -r'".format(ERRO, host))
            if err:
                print("{0}{1}".format(ERRO, err))
            if not out:
                print("{0}{1} got nothing".format(ERRO, host))
            err_cnt += 1
            continue
        try:
            short_kernel = out[:3]
            short_kernel_ver = float(short_kernel)
        except BaseException as e:
            print("{0}{1} tried to extract short kernel release ".format(ERRO,
                  host) + "but hit exception: {}".format(e))
            err_cnt += 1
            continue
        if short_kernel_ver < 3.1:
            print("{0}{1} has kernel release {2} which is not ".format(ERRO,
                  host, out) + "supported")
            err_cnt += 1
            continue
        for key, val in pkg_kv.items():
            if key == 'Version':
                continue
            if key == 'Tool' or key == 'NsdperfCommon':
                for pkg in val:
                    if pkg == 'fping':
                        _, _, rc = run_cmd_on_host(host, 'fping -v')
                        if rc != 0:
                            err_cnt += 1
                            print("{0}{1} does not have {2} ".format(ERRO, host,
                                  pkg) + "installed")
                            continue
                        else:
                            print("{0}{1} has {2} installed".format(INFO, host,
                                  pkg))
                    else:
                        rc = is_rpm_package_installed(host, pkg)
                        if rc is False:
                            err_cnt += 1
                        continue
            if hs_type == 'rdma':
                if key == 'NsdperfRDMA':
                    ker_pkgs = []
                    if short_kernel_ver == 3.1:
                        try:
                            ker_pkgs = val['Linux_kernel_3.1']
                        except KeyError as e:
                            err_cnt += 1
                            print("{0}{1} tried to extract RDMA ".format(ERRO,
                                  host) + "packages of certain kernel but hit " +
                                  "KeyError: {}".format(e))
                            continue
                    elif short_kernel_ver >= 4.1:
                        try:
                            ker_pkgs = val['Linux_kernel_4.1']
                        except KeyError as e:
                            err_cnt += 1
                            print("{0}{1} tried to extract RDMA ".format(ERRO,
                                  host) + "packages of certain kernel but hit " +
                                  "KeyError: {}".format(e))
                            continue
                    if not ker_pkgs:
                        err_cnt += 1
                        print("{0}{1} cannot get RDMA requried ".format(ERRO,
                              host) + "packages")
                        continue
                    for pkg in ker_pkgs:
                        rc = is_rpm_package_installed(host, pkg)
                        if rc is False:
                            err_cnt += 1
                        continue
        print('')
    if err_cnt > 0:
        print("{}Please install dependent packages according ".format(ERRO) +
              "to {} before running this tool".format(DEPE_PKG))
        sys.exit("{}Bye!\n".format(QUIT))
    return 0


def check_rdma_ports_up(
        host,
        rdma_ports):
    """
    Params:
        host: hostname list.
        rdma_ports: RDMA port list.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not host:
        err_cnt += 1
        print("{}Invalid parameter: host".format(ERRO))
    if not rdma_ports or isinstance(rdma_ports, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: rdma_ports".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    out, err, rc = run_cmd_on_host(host, 'ibdev2netdev')
    out = out.strip()
    err = err.strip()
    if rc != 0 or not out:
        print("{0}{1} failed to get RDMA port information ".format(ERRO,
              host) + "by running ibdev2netdev")
        sys.exit("{}Bye!\n".format(QUIT))

    port_num = len(rdma_ports)
    state_ok_cnt = 0
    out_lines = out.splitlines()
    for line in out_lines:
        for port in rdma_ports:
            if port in line and '(Up)' in line:
                state_ok_cnt += 1
                print("{0}{1} has '{2}' with 'Up' state".format(INFO,
                      host, port))
                continue
            if port in line and '(Up)' not in line:
                print("{0}{1} has '{2}' without 'Up' state".format(ERRO,
                      host, port))
                continue

    if state_ok_cnt != port_num:
        print("{0}Not all RDMA ports on {1} have 'Up' state".format(ERRO,
              host))
        sys.exit("{}Bye!\n".format(QUIT))
    else:
        return 0


def check_mlx_link_layer(
        hosts,
        mlx_port_csv):
    """
    Params:
        hosts: hostname list.
        mlx_port_csv: mlx port in CSV format.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        err_cnt += 1
    if not mlx_port_csv or isinstance(mlx_port_csv, str) is False:
        print("{}Invalid parameter: mlx_port_csv".format(ERRO))
        err_cnt += 1
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    port_num_list = mlx_port_csv.split(',')
    if not port_num_list:
        print("{}Failed to split port number list from ".format(ERRO) +
              "mlx_port_csv: {}".format(mlx_port_csv))
        sys.exit("{}Bye!\n".format(QUIT))
    mlx_ports = []
    for portnum in port_num_list:
        port_num_list = portnum.split('/')
        try:
            port = port_num_list[0]
        except IndexError as e:
            print("{0}Tried to extract port from {1} but ".format(ERRO,
                  port_num_list) + "hit exception: {}".format(e))
            sys.exit("{}Bye!\n".format(QUIT))
        mlx_ports.append(port)
    if not mlx_ports:
        print("{}Failed to extract mlx port".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    port_len = len(mlx_ports)
    for host in hosts:
        for port in mlx_ports:
            cmd = "ibstat {}".format(port)
            out, err, rc = run_cmd_on_host(host, cmd)
            out = out.strip()
            err = err.strip()
            if rc != 0:
                print("{0}{1} failed to run cmd: {2}".format(ERRO,
                      host, cmd))
                if err:
                    print("{0}{1}".format(ERRO, err))
                err_cnt += 1
                continue
            if not out:
                print("{0}{1} ran cmd: '{2}' but got ".format(ERRO,
                      host, cmd) + "nothing")
                err_cnt += 1
                continue
            if 'InfiniBand' in out:
                print("{0}{1} has '{2}' with InfiniBand ".format(INFO,
                      host, port) + "Link Layer")
                continue
            else:
                print("{0}{1} has '{2}' but its Link ".format(ERRO,
                      host, port) + "Layer is not InfiniBand")
                err_cnt += 1
                continue
        if port_len > 1:
            print('')
    if port_len == 1:
        print('')
    if err_cnt > 0:
        print("{}Not all mlx ports on all hosts have ".format(ERRO) +
              "correct Link Layer")
        sys.exit("{}Bye!\n".format(QUIT))
    return 0


def map_ib_to_ca_port(
        host,
        rdma_ports):
    """
    Params:
        host: hostname on which to check RDMA port.
        rdma_ports: RDMA port list.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not host:
        err_cnt += 1
        print("{}Invalid parameter: host".format(ERRO))
    if not rdma_ports or isinstance(rdma_ports, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: rdma_ports".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    out, err, rc = run_cmd_on_host(host, 'ibdev2netdev')
    out = out.strip()
    err = err.strip()
    if rc != 0:
        print("{0}{1} failed to run cmd: ibdev2netdev".format(ERRO, host))
        sys.exit("{}Bye!\n".format(QUIT))
    if not out:
        print("{0}{1} ran cmd: ibdev2netdev but got nothing".format(ERRO,
              host))
        sys.exit("{}Bye!\n".format(QUIT))

    port_kv = {}
    out_lines = out.splitlines()
    for line in out_lines:
        line_to_list = line.split()
        try:
            dev_name = line_to_list[4]
            mlx_name = line_to_list[0]
            port_num = line_to_list[2]
        except IndexError as e:
            print("{0}{1} tried to extract IB items but hit ".format(ERRO,
                  host) + "IndexError: {}".format(e))
            sys.exit("{}Bye!\n".format(QUIT))
        ca_name = "{0}/{1}".format(mlx_name, port_num)
        port_kv[dev_name] = ca_name
        if dev_name in rdma_ports:
            print("{0}{1} has '{2}' with CA(Channel Adapter) ".format(INFO,
                  host, dev_name) + "name '{}'".format(ca_name))

    if not port_kv:
        print("{0}{1} failed to generate RDMA port K-V pairs".format(ERRO,
              host))
        sys.exit("{}Bye!\n".format(QUIT))
    return port_kv


def generate_mlx_port_string(
        host_port_kv,
        rdma_ports):
    """
    Params:
        host_port_kv: Dictionary of host RDMA port.
        rdma_ports: RDMA port list.
    Returns:
        mlx_port_csv if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not host_port_kv or isinstance(host_port_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: host_port_kv".format(ERRO))
    if not rdma_ports or isinstance(rdma_ports, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: rdma_ports".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    port_len = len(rdma_ports)
    mlx_ports = []
    for host, port in host_port_kv.items():
        for key, val in port.items():
            if key in rdma_ports:
                mlx_ports.append(val)

    dedup_mlx_ports = list(set(mlx_ports))
    if len(dedup_mlx_ports) != port_len:
        print("{}There is host has different CA name ".format(ERRO) +
              "or CA port number")
        sys.exit("{}Bye!\n".format(QUIT))

    mlx_port_csv = ','.join(dedup_mlx_ports)
    return mlx_port_csv


def get_rdma_mlx_ports(
        hosts,
        rdma_ports):
    """
    Params:
        hosts: hostnames on which to check RDMA ports.
        rdma_ports: RDMA ports such as ['ib0', 'ib1'].
    Returns:
        mlx port in CSV format if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    for host in hosts:
        _, _, rc = run_cmd_on_host(host, 'which ibdev2netdev')
        if rc != 0:
            print("{0}{1} dose not have executable ibdev2netdev".format(
                  ERRO, host))
            err_cnt += 1
        _, _, rc = run_cmd_on_host(host, 'which ibstat')
        if rc != 0:
            print("{0}{1} dose not have executable ".format(ERRO, host) +
                  "ibstat")
            err_cnt += 1
    if err_cnt > 0:
        print("{0}Install required RDMA tools before running ".format(
              ERRO) + "this tool")
        sys.exit("{}Bye!\n".format(QUIT))

    port_err_cnt = 0
    for host in hosts:
        for port in rdma_ports:
            _, _, rc = run_cmd_on_host(host, "ifconfig {}".format(port))
            if rc != 0:
                port_err_cnt += 1
                print("{0}{1} does not have RDMA device ".format(ERRO,
                      host) + "port '{}'".format(port))
                continue
    if port_err_cnt > 0:
        print("{}Not all hosts have all specified RDMA ".format(ERRO) +
              "ports")
        sys.exit("{}Bye!\n".format(QUIT))

    host_port_kv = {}
    for host in hosts:
        check_rdma_ports_up(host, rdma_ports)
        dev_ca_kv = map_ib_to_ca_port(host, rdma_ports)
        host_port_kv[host] = dev_ca_kv
        print('')

    mlx_port_csv = generate_mlx_port_string(host_port_kv, rdma_ports)
    check_mlx_link_layer(hosts, mlx_port_csv)
    return mlx_port_csv


def is_valid_ipv4(address):
    """
    Params:
        address: IPv4 address.
    Returns:
        0 if given IP is legal IPv4 address.
        1 if not.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error as e:
            print("{0}{1} is not a valid IPv4. ".format(ERRO, address) +
                  "Hit exception: {}".format(e))
            return 1
        if address.count('.') == 3:
            return 0
        else:
            print("{0}{1} is not a valid IPv4".format(ERRO, address))
            return 1
    return 0


def are_hosts_ipv4(hosts):
    """
    Params:
        hosts: hostname list.
    Returns:
        0 if all hosts are IPv4 addresses.
        !0 if not.
    """
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        return 1
    err_cnt = 0
    for host in hosts:
        rc = is_valid_ipv4(host)
        if rc != 0:
            err_cnt += 1
    return err_cnt


def create_local_log_dir(foldername):
    """
    Params:
        foldername:
    Returns:
        full path of log dir.
        exit if hit error.
    """
    if not foldername or isinstance(foldername, str) is False:
        print("{}Invalid parameter: foldername".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    try:
        logdir = os.path.join(os.getcwd(), 'log', foldername)
        os.makedirs(logdir)
    except BaseException as e:
        print("{0}Tried to create log dir but hit exception: ".format(ERRO) +
              "{}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))
    return logdir


def remotely_create_log_dir(
        hosts,
        foldername):
    """
    Params:
        hosts: hostname list.
        foldername:
    Returns:
        full path of log dir.
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: hosts".format(ERRO))
    if not foldername or isinstance(foldername, str) is False:
        err_cnt += 1
        print("{}Invalid parameter: foldername".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))
    try:
        logdir = os.path.join(os.getcwd(), 'log', foldername)
    except BaseException as e:
        print("{0}Tried to join log dir but hit exception: ".format(ERRO) +
              "{}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))
    cmd = "mkdir -p {}".format(logdir)
    for host in hosts:
        _, _, rc = run_cmd_on_host(host, cmd)
        if rc != 0:
            err_cnt += 1
            print("{0}{1} failed to created {2}".format(ERRO, host, logdir))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))
    else:
        return logdir


def run_fping_test(
        hosts,
        logdir,
        fping_count):
    """
    Params:
        hosts: hostname list.
        logdir:
        fping_count:
    Returns:
        fping_out_kv = {
            'ip': 'output_filepath',
            ...
        }
        exit if hit error.
    """
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: hosts".format(ERRO))
    if not logdir or isinstance(logdir, str) is False:
        err_cnt += 1
        print("{}Invalid parameter: logdir".format(ERRO))
    if isinstance(fping_count, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: fping_count".format(ERRO))
    if fping_count < 2:
        err_cnt += 1
        print("{0}fping_count {1} is too little".format(ERRO, fping_count))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    try:
        fping_hosts = sorted(list(set(hosts)))
    except BaseException as e:
        print("{}Tried to generate fping host string but ".format(ERRO) +
              "hit exception: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))

    fping_out_kv = {}
    print("{}Starts 1 to n fping instances".format(INFO))
    for srchost in fping_hosts:
        print("{0}{1} starts fping instance to all hosts".format(INFO,
              srchost))
        print("{0}It will take at least {1} sec".format(INFO, fping_count))
        filepath = os.path.join(
                       logdir,
                       "from_{}_to_all.fping".format(srchost))
        cmd = 'ssh -o StrictHostKeyChecking=no -o LogLevel=error ' + \
              "{0} fping -C {1} ".format(srchost, fping_count) + \
              " -q -A {}".format(' '.join(fping_hosts))
        with open(filepath, 'wb') as fh:
            try:
                child = Popen(
                            shlex.split(cmd),
                            stderr=STDOUT,
                            stdout=fh)
                child.wait()
            except BaseException as e:
                print("{0}{1} tried to run fping ".format(ERRO, srchost) +
                      "but hit exception: {}".format(e))
                sys.exit("{}Bye!\n".format(QUIT))
        fping_out_kv[srchost] = filepath
        print("{0}{1} completed fping test".format(INFO, srchost))
    print('')
    if not fping_out_kv:
        print("{}Falied to generate fping output K-V".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    return fping_out_kv


def run_nsdperf_test(
        hosts,
        logdir,
        ttime_per_inst,
        test_thread,
        para_conn,
        buff_size,
        socket_size,
        rdma_test=False,
        mlx_port_csv=''):
    """
    Params:
        hosts: hostname list.
        logdir:
        ttime_per_inst:
        test_thread:
        para_conn:
        buff_size:
        socket_size:
        rdma_test:
        mlx_port_csv:
    Returns:
        nsdperf_out_kv = {
            'o2m': {
                'ip': 'output_filepath',
                ...
            },
            'm2m': 'output_filepath'
        }
        exit if hit error.
    """
    throughput_json_files_list = []
    err_cnt = 0
    if not hosts or isinstance(hosts, list) is False:
        err_cnt += 1
        print("{}Invalid parameter: hosts".format(ERRO))
    if not logdir or isinstance(logdir, str) is False:
        err_cnt += 1
        print("{}Invalid parameter: logdir".format(ERRO))
    if isinstance(ttime_per_inst, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: ttime_per_inst".format(ERRO))
    if ttime_per_inst < 10:
        err_cnt += 1
        print("{}ttime_per_inst is too little".format(ERRO))
    if isinstance(test_thread, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: test_thread".format(ERRO))
    if test_thread < 1 or test_thread > MAX_TESTERS:
        err_cnt += 1
        print("{}test_thread is out of range".format(ERRO))
    if isinstance(para_conn, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: para_conn".format(ERRO))
    if para_conn < 1 or para_conn > MAX_PARALLEL:
        err_cnt += 1
        print("{}para_conn is out of range".format(ERRO))
    if isinstance(buff_size, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: buff_size".format(ERRO))
    if buff_size < MIN_BUFFSIZE or buff_size > MAX_BUFFSIZE:
        err_cnt += 1
        print("{}buff_size is out of range".format(ERRO))
    if isinstance(socket_size, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: socket_size".format(ERRO))
    if socket_size < 0 or socket_size > MAX_SOCKSIZE:
        err_cnt += 1
        print("{}socket_size is out of range".format(ERRO))
    if isinstance(rdma_test, bool) is False:
        err_cnt += 1
        print("{}Invalid parameter: rdma_test".format(ERRO))
    if rdma_test is True:
        if not mlx_port_csv or \
            isinstance(mlx_port_csv, str) is False:
            err_cnt += 1
            print("{}Invalid parameter: mlx_port_csv".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    nsdperftool_log = os.path.join(logdir, 'nsdperfTool.out')
    ori_nsdperf_out_file = os.path.join(logdir, 'nsdperfResult.json')
    o2m_kv = {}
    print("{}Starts one to many nsdperf instances".format(INFO))
    for client in hosts:
        print("{0}{1} starts nsdperf instance to all nodes".format(INFO,
              client))
        print("{0}It will take at least {1} sec".format(INFO, ttime_per_inst))
        servers = [i for i in hosts if i != client]
        if not servers:
            print("{0}Failed to generate servers for client {1}".format(ERRO,
                  client))
            sys.exit("{}Bye!\n".format(QUIT))
        server_csv = ','.join(servers)
        pre_cmd = "{0} -t read -k {1} -b {2} ".format(NSDTOOL, socket_size, \
                  buff_size) + "-W {0} -T {0} -P {1} -d {2} ".format( \
                  test_thread, para_conn, logdir) + " -s {} ".format( \
                  server_csv) + "-c {0} -l {1}".format(client, ttime_per_inst)
        cmd = ''
        if rdma_test is True:
            cmd = "{0} -p {1}".format(pre_cmd, mlx_port_csv)
        else:
            # History: nReceivers = 256, nWorkers = 256, nTesterThreads = 256
            cmd = pre_cmd

        if PYTHON2 is False:
            cmd = "python3 {}".format(cmd)
        else:                 
            cmd = "python2 {}".format(cmd)

        with open(nsdperftool_log, 'a') as fh:
            try:
                child = Popen(
                            shlex.split(cmd),
                            stderr=STDOUT,
                            stdout=fh)
                child.wait()
            except BaseException as e:
                print("{0}Tried to run {1} but hit ".format(ERRO, NSDTOOL) +
                      "exception: {}".format(e))
                sys.exit("{}Bye!\n".format(QUIT))
        # Copy the file to avoid overwrite it
        nsdperf_out = os.path.join(
                          logdir,
                          "from_{}_to_all.nsdperf.json".format(client))
        try:
            copyfile(ori_nsdperf_out_file, nsdperf_out)
        except BaseException as e:
            print("{0}Tried to copy {1} to {2} but hit ".format(ERRO,
                  ori_nsdperf_out_file, nsdperf_out) + "exception: " +
                  "{}".format(e))
            sys.exit("{}Bye!\n".format(QUIT))
        o2m_kv[client] = nsdperf_out
        print("{0}nsdperf instance from {1} to other hosts ".format(INFO,
              client) + "completed")
    print('')

    try:
        mid = int(len(hosts) / 2)
        clients = hosts[mid:]
        servers = hosts[:mid]
    except BaseException as e:
        print("{}Tried to generate clients and servers ".format(ERRO) +
              "from hosts but hit exception: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))

    client_csv = ','.join(clients)
    server_csv = ','.join(servers)
    pre_cmd = "{0} -t read -k {1} -b {2} ".format(NSDTOOL, socket_size, \
              buff_size) + "-W {0} -T {0} -P {1} -d {2} ".format( \
              test_thread, para_conn, logdir) + " -s {} ".format( \
              server_csv) + "-c {0} -l {1}".format(client_csv,
              ttime_per_inst)
    cmd = ''
    if rdma_test is True:
        cmd = "{0} -p {1}".format(pre_cmd, mlx_port_csv)
    else:
        # History: nReceivers = 256, nWorkers = 256, nTesterThreads = 256
        cmd = pre_cmd

    if PYTHON2 is False:
        cmd = "python3 {}".format(cmd)
    else:
        cmd = "python2 {}".format(cmd)

    print("{}Starts many to many nsdperf instance".format(INFO))
    print("{0}It will take at least {1} sec".format(INFO, ttime_per_inst))
    with open(nsdperftool_log, 'a') as fh:
        try:
            child = Popen(
                        shlex.split(cmd),
                        stderr=STDOUT,
                        stdout=fh)
            child.wait()
        except BaseException as e:
            print("{0}Tried to run {1} but hit ".format(ERRO, NSDTOOL) +
                  "exception: {}".format(e))
            sys.exit("{}Bye!\n".format(QUIT))
    # Copy the file to avoid overwrite it
    nsdperf_out = os.path.join(logdir, 'many_to_many.nsdperf.json')
    try:
        copyfile(ori_nsdperf_out_file, nsdperf_out)
    except BaseException as e:
        print("{0}Tried to copy {1} to {2} but hit ".format(ERRO,
              ori_nsdperf_out_file, nsdperf_out) + "exception: " +
              "{}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))
    print("{0}Many to many nsdperf instance completed".format(INFO,
          client))
    nsdperf_out_kv = {}
    nsdperf_out_kv['o2m'] = o2m_kv
    nsdperf_out_kv['m2m'] = nsdperf_out
    return nsdperf_out_kv


def calc_mean_from_list(alist):
    """
    Params:
        alist: a number list.
    Returns:
        the mean value of the list.
        exit if hit error.
    """
    if not alist or isinstance(alist, list) is False:
        print("{}Invalid parameter: alist".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    alen = len(alist)
    blist = []
    for i in alist:
        float_i = 0.00
        # replace timeout string "-" to 1000.00 msec
        if i == '-':
            float_i = 1000.00
        else:
            float_i = float(i)
        blist.append(float_i)
    blen = len(blist)
    if alen != blen:
        print("{0}Failed to format original list {1}".format(ERRO, alist))
        sys.exit("{}Bye!\n".format(QUIT))

    mean_val = float(sum(blist) / blen)
    mean_val = float("{:.2f}".format(mean_val))
    return mean_val


def calc_max_from_list(alist):
    """
    Params:
        alist: a number list.
    Returns:
        the maximum value of the list.
        exit if hit error.
    """
    if not alist or isinstance(alist, list) is False:
        print("{}Invalid parameter: alist".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    alen = len(alist)
    blist = []
    for i in alist:
        float_i = 0.00
        # replace timeout string "-" to 1000.00 msec
        if i == '-':
            float_i = 1000.00
        else:
            float_i = float(i)
        blist.append(float_i)
    blen = len(blist)
    if alen != blen:
        print("{0}Failed to format original list {1}".format(ERRO, alist))
        sys.exit("{}Bye!\n".format(QUIT))

    max_val = max(blist)
    max_val = float("{:.2f}".format(max_val))
    return max_val


def calc_min_from_list(alist):
    """
    Params:
        alist: a number list.
    Returns:
        the minimum value of the list.
        exit if hit error.
    """
    if not alist or isinstance(alist, list) is False:
        print("{}Invalid parameter: alist".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    alen = len(alist)
    blist = []
    for i in alist:
        float_i = 0.00
        # replace timeout string "-" to 1000.00 msec
        if i == '-':
            float_i = 1000.00
        else:
            float_i = float(i)
        blist.append(float_i)
    blen = len(blist)
    if alen != blen:
        print("{0}Failed to format original list {1}".format(ERRO, alist))
        sys.exit("{}Bye!\n".format(QUIT))

    min_val = min(blist)
    min_val = float("{:.2f}".format(min_val))
    return min_val


def calc_stddev_from_list(
        alist,
        mean):
    """
    Params:
        alist: a number list.
        mean: the mean value of given list.
    Returns:
        the standard deviation of the list.
        exit if hit error.
    """
    if not alist or isinstance(alist, list) is False:
        print("{}Invalid parameter: alist".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    if isinstance(mean, (int, float)) is False:
        print("{}Invalid parameter: mean".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    alen = len(alist)
    blist = []
    for i in alist:
        float_i = 0.00
        # replace timeout string "-" to 1000.00 msec
        if i == '-':
            float_i = 1000.00
        else:
            float_i = float(i)
        blist.append(float_i)
    blen = len(blist)
    if alen != blen:
        print("{0}Failed to format original list {1}".format(ERRO, alist))
        sys.exit("{}Bye!\n".format(QUIT))

    stddev_val = 0.0
    if PYTHON2 is False:
        try:
            stddev_val = statistics.stdev(blist)
        except statistics.StatisticsError:
            # Assuming the error is due 2 hosts, not ideal
            stddev_val = 0.0
    else:
        try:
            stddev_val = sqrt(
                             float(
                                 reduce(
                                     lambda x, y: x + y, map(
                                         lambda x: (x - mean) ** 2,
                                         blist)
                                       )
                                  ) / blen)
        except TypeError:
            # Assuming the error is due 2 hosts, not ideal
            stddev_val = 0.0

    stddev_val = float("{:.2f}".format(stddev_val))
    return stddev_val


def calc_diff_from_list(alist):
    """
    Params:
        alist: a number list.
    Returns:
        the minimum value of the list.
        exit if hit error.
    """
    if not alist or isinstance(alist, list) is False:
        print("{}Invalid parameter: alist".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    try:
        # (max - min) / max = 1 - min / max
        diff_pct = 100.0 - calc_min_from_list(alist) * 100.0 / calc_max_from_list(alist)
    except BaseException as e:
        print("{}Tried to calculate difference ".format(ERRO) +
              "percentage but hit exception: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))
    diff_pct = float("{:.2f}".format(diff_pct))
    return diff_pct


def check_file_exists(filepath):
    """
    Params:
        filepath:
    Returns:
        0 if filepath exists.
        exit if hit error.
    """
    if not filepath or isinstance(filepath, str) is False:
        print("{}Invalid parameter: filepath".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))
    if os.path.isfile(filepath) is True:
        return 0
    else:
        print("{0}{1} does NOT exist".format(ERRO, filepath))
        sys.exit("{}Bye!\n".format(QUIT))


def load_fping_test_result(out_file_kv):
    """
    Params:
        out_file_kv: file path K-V of fping output.
    Returns:
        multpile Python dictionaries if succeeded.
        exit if hit error.
    """
    if not out_file_kv or isinstance(out_file_kv, dict) is False:
        print("{}Invalid parameter: out_file_kv".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    all_fping_avg_lat_kv = {}
    all_fping_max_lat_kv = {}
    all_fping_min_lat_kv = {}
    all_fping_stddev_kv = {}
    for key, val in out_file_kv.items():
        check_file_exists(val)
        avg_lat = 0.0
        max_lat = 0.0
        min_lat = 0.0
        stddev_lat = 0.0
        try:
            with open(val, 'r') as fh:
                avgs = []
                maxs = []
                mins = []
                for line in fh.readlines():
                    line_to_list = line.split(':')
                    host_ip = line_to_list[0].strip()
                    # ignore local ip
                    if key == host_ip:
                        continue
                    lat_str = line_to_list[1].strip()
                    lats = lat_str.split()
                    hst_avg_lat = calc_mean_from_list(lats)
                    hst_max_lat = calc_max_from_list(lats)
                    hst_min_lat = calc_min_from_list(lats)
                    avgs.append(hst_avg_lat)
                    maxs.append(hst_max_lat)
                    mins.append(hst_min_lat)
                avg_lat = calc_mean_from_list(avgs)
                max_lat = calc_max_from_list(maxs)
                min_lat = calc_min_from_list(mins)
                stddev_lat = calc_stddev_from_list(avgs, avg_lat)
        except BaseException as e:
            print("{}Tried to extract fping result from ".format(ERRO) +
                  "'{0}' but hit exception: {1}".format(val, e))
            sys.exit("{}Bye!\n".format(QUIT))
        all_fping_avg_lat_kv[key] = avg_lat
        all_fping_max_lat_kv[key] = max_lat
        all_fping_min_lat_kv[key] = min_lat
        all_fping_stddev_kv[key] = stddev_lat
    return (all_fping_avg_lat_kv, all_fping_max_lat_kv,
            all_fping_min_lat_kv, all_fping_stddev_kv)


def load_nsdperf_test_result(out_file_kv):
    """
    Params:
        out_file_kv: file path K-V of fping output.
    Returns:
        multpile Python dictionaries if succeeded.
        exit if hit error.
    """
    if not out_file_kv or isinstance(out_file_kv, dict) is False:
        print("{}Invalid parameter: out_file_kv".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    o2m_kv = {}
    m2m_out = ''
    try:
        o2m_kv = out_file_kv['o2m']
        m2m_out = out_file_kv['m2m']
    except KeyError as e:
        print("{}Tried to extract nsdperf output file info ".format(ERRO) +
             "but hit KeyError: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))

    o2m_thrput_kv = {}
    o2m_thrputs = []
    o2m_lat_kv = {}
    o2m_lat_stddev_kv = {}
    o2m_rxe_kv = {}
    o2m_txe_kv = {}
    o2m_retr_kv = {}
    for key, val in o2m_kv.items():
        check_file_exists(val)
        perf_kv = load_json(val)
        if perf_kv is None:
            print("{}Bye!\n".format(QUIT))
        try:
            thrput = perf_kv['throughput(MB/sec)']
            network_lat = perf_kv['networkDelay'][0]['average']
            network_lat_stddev = perf_kv['networkDelay'][0]['standardDeviation']
            rxe = perf_kv['netData'][key]['rxerrors']
            txe = perf_kv['netData'][key]['txerrors']
            retr = perf_kv['netData'][key]['retransmit']
        except BaseException as e:
            print("{}Tried to extract items from 1:m nsdperf ".format(ERRO) +
                  "test result but hit exception: {}".format(e))
            print("{}Bye!\n".format(QUIT))
        o2m_thrput_kv[key] = thrput
        o2m_thrputs.append(thrput)
        o2m_lat_kv[key] = network_lat
        o2m_lat_stddev_kv[key] = network_lat_stddev
        o2m_rxe_kv[key] = rxe
        o2m_txe_kv[key] = txe
        o2m_retr_kv[key] = retr

    o2m_avg_thrput = calc_mean_from_list(o2m_thrputs)
    o2m_max_thrput = calc_max_from_list(o2m_thrputs)
    o2m_min_thrput = calc_min_from_list(o2m_thrputs)
    o2m_thrput_stddev = calc_stddev_from_list(o2m_thrputs, o2m_avg_thrput)
    o2m_thrput_diff_pct = calc_diff_from_list(o2m_thrputs)

    check_file_exists(m2m_out)
    perf_kv = load_json(m2m_out)
    if perf_kv is None:
        print("{}Bye!\n".format(QUIT))

    try:
        clients = perf_kv['client(s)']
    except KeyError as e:
        print("{}Tried to extract clients from m:m nsdperf ".format(ERRO) +
             "test result but hit KeyError: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))

    try:
        m2m_thrput = float(perf_kv['throughput(MB/sec)'])
        m2m_lat = float(perf_kv['networkDelay'][0]['average'])
        m2m_lat_stddev = float(
                            perf_kv['networkDelay'][0]['standardDeviation'])
    except BaseException as e:
        print("{}Tried to extract summary items from m:m ".format(ERRO) +
              "nsdperf test result but hit exception: {}".format(e))
        print("{}Bye!\n".format(QUIT))

    m2m_rxe_kv = {}
    m2m_txe_kv = {}
    m2m_retr_kv = {}
    for cli in clients:
        try:
            rxe = perf_kv['netData'][cli]['rxerrors']
            txe = perf_kv['netData'][cli]['txerrors']
            retr = perf_kv['netData'][cli]['retransmit']
        except BaseException as e:
            print("{}Tried to extract client items from m:m ".format(ERRO) +
                  "nsdperf test result but hit exception: {}".format(e))
            print("{}Bye!\n".format(QUIT))
        m2m_rxe_kv[cli] = rxe
        m2m_txe_kv[cli] = txe
        m2m_retr_kv[cli] = retr

    return (o2m_thrput_kv, o2m_lat_kv, o2m_lat_stddev_kv, o2m_rxe_kv,
            o2m_txe_kv, o2m_retr_kv, o2m_avg_thrput, o2m_max_thrput, o2m_min_thrput,
            o2m_thrput_stddev, o2m_thrput_diff_pct, m2m_thrput, m2m_lat,
            m2m_lat_stddev, m2m_rxe_kv, m2m_txe_kv, m2m_retr_kv)


def save_throughput_to_csv(
        logdir,
        o2m_thrput_kv,
        m2m_thrput):
    """
    Params:
        logdir: log path.
        o2m_thrput_kv: one to many throughput performance number.
        m2m_thrput: many to many throughput performance number.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    err_cnt = 0
    if not logdir or isinstance(logdir, str) is False:
        err_cnt += 1
        print("{}Invalid parameter: logdir".format(ERRO))
    if os.path.isdir(logdir) is False:
        err_cnt += 1
        print("{0}{1} does NOT exist".format(ERRO, logdir))
    if not o2m_thrput_kv or isinstance(o2m_thrput_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_thrput_kv".format(ERRO))
    if isinstance(m2m_thrput, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_thrput".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    filepath = os.path.join(logdir, 'nsd_throughput.csv')
    try:
        with open(filepath, 'w') as fh:
            csv_writer = csv.writer(fh)
            csv_writer.writerow(["Host", "Throughput MB/sec"])
            for key, val in o2m_thrput_kv.items():
                csv_writer.writerow([key, val])
            csv_writer.writerow(["manyToMany", m2m_thrput])
        print('')
        print("{0}Summary of NSD throughput can be found in {1}".format(
              INFO, filepath))
    except BaseException as e:
        print("{0}Cannot write nsd_throughput.csv file to {1}".format(ERRO,
              logdir))
        sys.exit("{}Bye!\n".format(QUIT))


def check_nsd_kpi(
        o2m_thrput_kv,
        o2m_avg_thrput,
        o2m_max_thrput,
        o2m_min_thrput,
        o2m_thrput_stddev,
        o2m_thrput_diff_pct,
        o2m_lat_kv,
        o2m_lat_stddev_kv,
        o2m_rxe_kv,
        o2m_txe_kv,
        o2m_retr_kv,
        m2m_thrput,
        m2m_lat,
        m2m_lat_stddev,
        m2m_rxe_kv,
        m2m_txe_kv,
        m2m_retr_kv):
    """
    Params:
        o2m_thrput_kv:
        o2m_avg_thrput:
        o2m_max_thrput:
        o2m_min_thrput:
        o2m_thrput_stddev:
        o2m_thrput_diff_pct:
        o2m_lat_kv:
        o2m_lat_stddev_kv:
        o2m_rxe_kv:
        o2m_txe_kv:
        o2m_retr_kv:
        m2m_thrput:
        m2m_lat:
        m2m_lat_stddev:
        m2m_rxe_kv:
        m2m_txe_kv:
        m2m_retr_kv:
    Returns:
        0 if succeeded.
        !0 if hit error.
    """
    err_cnt = 0
    if not o2m_thrput_kv or isinstance(o2m_thrput_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_thrput_kv".format(ERRO))
    if isinstance(o2m_avg_thrput, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_avg_thrput".format(ERRO))
    if isinstance(o2m_max_thrput, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_max_thrput".format(ERRO))
    if isinstance(o2m_min_thrput, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_min_thrput".format(ERRO))
    if isinstance(o2m_thrput_stddev, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_thrput_stddev".format(ERRO))
    if isinstance(o2m_thrput_diff_pct, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_thrput_diff_pct".format(ERRO))
    if not o2m_lat_kv or isinstance(o2m_lat_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_lat_kv".format(ERRO))
    if not o2m_lat_stddev_kv or isinstance(o2m_lat_stddev_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_lat_stddev_kv".format(ERRO))
    if not o2m_rxe_kv or isinstance(o2m_rxe_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_rxe_kv".format(ERRO))
    if not o2m_txe_kv or isinstance(o2m_txe_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_txe_kv".format(ERRO))
    if not o2m_retr_kv or isinstance(o2m_retr_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: o2m_retr_kv".format(ERRO))
    if isinstance(m2m_thrput, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_thrput".format(ERRO))
    if isinstance(m2m_lat, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_lat".format(ERRO))
    if isinstance(m2m_lat_stddev, (int, float)) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_lat_stddev".format(ERRO))
    if not m2m_rxe_kv or isinstance(m2m_rxe_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_rxe_kv".format(ERRO))
    if not m2m_txe_kv or isinstance(m2m_txe_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_txe_kv".format(ERRO))
    if not m2m_retr_kv or isinstance(m2m_retr_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: m2m_retr_kv".format(ERRO))
    if err_cnt > 0:
        return err_cnt

    print("{}Throughput results of nsdperf 1:m test".format(INFO))
    for key, val in o2m_thrput_kv.items():
        if float(val) < KPI_NSD_THROUGH:
            err_cnt += 1
            print("{0}{1} has {2} MB/sec network throughput ".format(ERRO,
                  key, val) + "which is less than the required " +
                  "{} MB/sec throughput KPI".format(KPI_NSD_THROUGH))
        else:
            print("{0}{1} has {2} MB/sec network throughput ".format(INFO,
                  key, val) + "which meets the required " +
                  "{} MB/sec throughput KPI".format(KPI_NSD_THROUGH))
    print("{0}The average network throughput is {1} MB/sec".format(INFO,
          o2m_avg_thrput))
    print("{0}The maximum network throughput is {1} MB/sec".format(INFO,
          o2m_max_thrput))
    print("{0}The minimum network throughput is {1} MB/sec".format(INFO,
          o2m_min_thrput))
    print("{}The standard deviation of network throughput ".format(INFO) +
          "is {} MB/sec".format(o2m_thrput_stddev))
    print("{}Define difference percentage as 100 * (max - min) ".format(
          INFO) + "/ max")
    if o2m_thrput_diff_pct > KPI_DIFF_PCT:
        err_cnt += 1
        print("{0}All hosts have {1}% network throughput ".format(ERRO,
              o2m_thrput_diff_pct) + "difference which is more than " +
              "the required {}% difference KPI".format(KPI_DIFF_PCT))
    else:
        print("{0}All hosts have {1}% network throughput ".format(INFO,
              o2m_thrput_diff_pct) + "difference which meets the " +
              "required {}% difference KPI".format(KPI_DIFF_PCT))

    print('')
    print("{}Latency results of nsdperf 1:m test".format(INFO))
    for key, val in o2m_lat_kv.items():
        print("{0}{1} has {2} msec average NSD latency".format(INFO, key,
              val))
    for key, val in o2m_lat_stddev_kv.items():
        print("{0}{1} has {2} msec standard deviation of NSD ".format(INFO,
              key, val) + "latency")

    print('')
    print("{}Packet results of nsdperf 1:m test".format(INFO))
    for key, val in o2m_rxe_kv.items():
        print("{0}{1} has {2} packet NSD Rx error".format(INFO, key, val))
    for key, val in o2m_txe_kv.items():
        print("{0}{1} has {2} packet NSD Tx error".format(INFO, key, val))
    for key, val in o2m_retr_kv.items():
        print("{0}{1} has retransmit {2} NSD packet".format(INFO, key,
              val))

    print('')
    print("{}Throughput results of nsdperf m:m test".format(INFO))
    print("{0}Many to many network throughput is {1} MB/sec".format(INFO,
          m2m_thrput))

    print('')
    print("{}Latency results of nsdperf m:m test".format(INFO))
    print("{0}Many to many average NSD latency is {1} msec".format(INFO,
          m2m_lat))
    print("{}Many to many standard deviation of NSD ".format(INFO) +
          "latency is {} msec".format(m2m_lat_stddev))

    print('')
    print("{}Packet results of nsdperf m:m test".format(INFO))
    packets_rxe = 0
    for pkt in m2m_rxe_kv.values():
        packets_rxe += pkt
    print("{0}Many to many NSD Rx total error is {1} packet".format(INFO,
          packets_rxe))
    packets_txe = 0
    for pkt in m2m_txe_kv.values():
        packets_txe += pkt
    print("{0}Many to many NSD Rx total error is {1} packet".format(INFO,
          packets_txe))
    packets_rtr = 0
    for pkt in m2m_retr_kv.values():
        packets_rtr += pkt
    print("{0}Many to many NSD total retransmit is {1} packet".format(INFO,
          packets_rtr))
    return err_cnt


def check_fping_kpi(
        fping_avg_lat_kv,
        fping_max_lat_kv,
        fping_min_lat_kv,
        fping_stddev_kv,
        test_string,
        rdma_test=False):
    """
    Params:
        fping_avg_lat_kv:
        fping_max_lat_kv:
        fping_min_lat_kv:
        fping_stddev_kv:
        test_string:
        rdma_test:
    Returns:
        0 if succeeded.
        !0 if hit error.
    """
    err_cnt = 0
    if not fping_avg_lat_kv or isinstance(fping_avg_lat_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: fping_avg_lat_kv".format(ERRO))
    if not fping_max_lat_kv or \
        isinstance(fping_max_lat_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: fping_max_lat_kv".format(ERRO))
    if not fping_min_lat_kv or \
        isinstance(fping_min_lat_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: fping_min_lat_kv".format(ERRO))
    if not fping_stddev_kv or \
        isinstance(fping_stddev_kv, dict) is False:
        err_cnt += 1
        print("{}Invalid parameter: fping_stddev_kv".format(ERRO))
    if not test_string or isinstance(test_string, str) is False:
        err_cnt += 1
        print("{}Invalid parameter: test_string".format(ERRO))
    if isinstance(rdma_test, bool) is False:
        err_cnt += 1
        print("{}Invalid parameter: rdma_test".format(ERRO))
    if err_cnt > 0:
        return err_cnt

    print('')
    print("{0}ICMP latency results of fping {1} test".format(INFO,
          test_string))
    for key, val in fping_avg_lat_kv.items():
        if val > KPI_MAX_LATENCY:
            if rdma_test is True:
                if val > 2 * KPI_AVG_LATENCY:
                    err_cnt += 1
                    print("{0}{1} has {2} msec ICMP average ".format(ERRO,
                          key, val) + "latency which is greater than " +
                          "the duple required average latency KPI " +
                          "{} msec".format(KPI_AVG_LATENCY))
                else:
                    print("{0}{1} has {2} msec ICMP average ".format(WARN,
                          key, val) + "latency which is greater than " +
                          "the required average latency KPI {} ".format(
                          KPI_AVG_LATENCY) + "msec")
            else:
                err_cnt += 1
                print("{0}{1} has {2} msec ICMP average ".format(ERRO, key,
                      val) + "latency which is greater than the required " +
                      "average latency KPI {} msec".format(KPI_AVG_LATENCY))
        else:
            print("{0}{1} has {2} msec ICMP average latency ".format(INFO,
                  key, val) + "which meets the required average latency " +
                  "KPI {} msec".format(KPI_AVG_LATENCY))

    print('')
    for key, val in fping_max_lat_kv.items():
        if val > KPI_MAX_LATENCY:
            if rdma_test is True:
                print("{0}{1} has {2} msec ICMP maximum ".format(WARN, key,
                      val) + "latency which is greater than the required " +
                      "maximum latency KPI {} msec".format(KPI_MAX_LATENCY))
            else:
                err_cnt += 1
                print("{0}{1} has {2} msec ICMP maximum ".format(ERRO, key,
                      val) + "latency which is greater than the required " +
                      "maximum latency KPI {} msec".format(KPI_MAX_LATENCY))
        else:
            print("{0}{1} has {2} msec ICMP maximum latency ".format(INFO,
                  key, val) + "which meets the required maximum latency " +
                  "KPI {} msec".format(KPI_MAX_LATENCY))

    print('')
    for key, val in fping_min_lat_kv.items():
        if val > KPI_AVG_LATENCY:
            if rdma_test is True:
                print("{0}{1} has {2} msec ICMP minimum ".format(WARN, key,
                      val) + "latency which is greater than the required " +
                      "average latency KPI {} msec".format(KPI_AVG_LATENCY))
            else:
                err_cnt += 1
                print("{0}{1} has {2} msec ICMP minimum ".format(ERRO, key,
                      val) + "latency which is greater than the required " +
                      "average latency KPI {} msec".format(KPI_AVG_LATENCY))
        else:
            print("{0}{1} has {2} msec ICMP minimum latency ".format(INFO,
                  key, val) + "which meets the required average latency " +
                  "KPI {} msec".format(KPI_AVG_LATENCY))

    print('')
    for key, val in fping_stddev_kv.items():
        if val > KPI_STDDEV_LAT:
            if rdma_test is True:
                print("{0}{1} has {2} msec ICMP latency ".format(WARN, key,
                      val) + "standard deviation which is greater than " +
                      "the required latency standard deviation KPI " +
                      "{} msec".format(KPI_STDDEV_LAT))
            else:
                err_cnt += 1
                print("{0}{1} has {2} msec ICMP latency ".format(ERRO, key,
                      val) + "standard deviation which is greater than " +
                      "the required latency standard deviation KPI " +
                      "{} msec".format(KPI_STDDEV_LAT))
        else:
            print("{0}{1} has {2} msec ICMP latency standard ".format(INFO,
                  key, val) + "deviation which meets the required " +
                  "latency standard deviation KPI {} msec".format(
                  KPI_STDDEV_LAT))
    print('')
    return err_cnt


def check_passwordless_ssh(hosts):
    """
    Params:
        hosts: hostname list.
    Returns:
        0 if succeeded.
        exit if hit error.
    """
    if not hosts or isinstance(hosts, list) is False:
        print("{}Invalid parameter: hosts".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    err_cnt = 0
    for host in hosts:
        nokey_check_cmds = ['ssh',
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'BatchMode=yes',
                            '-o', 'ConnectTimeout=5',
                            '-o', 'LogLevel=error',
                            host,
                            'uname']
        try:
            child = Popen(nokey_check_cmds, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            _, _ = child.communicate()
            rc = child.returncode
        except BaseException as e:
            err_cnt += 1
            print("{0}Tried to run cmd '{1}' but hit exception: ".format(ERRO,
                  " ".join(nokey_check_cmds)) + "{}".format(e))
        if rc == 0:
            print("{0}localhost succeeded to passwordless ssh {1}".format(INFO,
                  host))
        else:
            err_cnt += 1
            print("{0}localhost failed to passwordless ssh {1}".format(ERRO,
                  host))

        key_check_cmds = ['ssh',
                          '-o', 'StrictHostKeyChecking=yes',
                          '-o', 'BatchMode=yes',
                          '-o', 'ConnectTimeout=5',
                          '-o', 'LogLevel=error',
                          host,
                          'uname']
        try:
            child = Popen(key_check_cmds, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            _, _ = child.communicate()
            rc = child.returncode
        except BaseException as e:
            err_cnt += 1
            print("{0}Tried to run cmd '{1}' but hit exception: ".format(ERRO,
                  ' '.join(key_check_cmds)) + "{}".format(e))
            continue
        if rc == 0:
            print("{0}localhost succeeded to passwordless ssh {1} ".format(INFO,
                  host) + "with strict host key checking")
        else:
            err_cnt += 1
            print("{0}localhost failed to passwordless ssh {1} ".format(ERRO,
                  host) + "with strict host key checking")
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))
    else:
        print('')
        return 0


def print_end_summary(
        fp_err_cnt,
        nsd_err_cnt,
        acceptance_flag):
    """
    Params:
        fp_err_cnt:
        nsd_err_cnt:
        acceptance_flag:
    Returns:
        0 if succeeded.
        !0 if hit error.
    """
    err_cnt = 0
    if isinstance(fp_err_cnt, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: fp_err_cnt".format(ERRO))
    if isinstance(nsd_err_cnt, int) is False:
        err_cnt += 1
        print("{}Invalid parameter: nsd_err_cnt".format(ERRO))
    if isinstance(acceptance_flag, bool) is False:
        err_cnt += 1
        print("{}Invalid parameter: acceptance_flag".format(ERRO))
    if err_cnt > 0:
        sys.exit("{}Bye!\n".format(QUIT))

    print('')
    print("{}Summary of this instance".format(INFO))
    if fp_err_cnt == 0:
        print("{}All fping tests are passed".format(INFO))
    elif fp_err_cnt == 1:
        print("{}The fping tests failed 1 time".format(ERRO))
    else:
        print("{0}The fping tests failed {1} times".format(ERRO,
              fp_err_cnt))
    err_cnt += fp_err_cnt

    if nsd_err_cnt == 0:
        print("{}All nsdperf tests are passed".format(INFO))
    elif nsd_err_cnt == 1:
        print("{}The nsdperf tests failed 1 time".format(ERRO))
    else:
        print("{0}The nsdperf tests failed {1} times".format(ERRO,
              nsd_err_cnt))
    err_cnt += nsd_err_cnt
    print('')

    if err_cnt == 0:
        if acceptance_flag is True:
            print("{}All network tests have passed. You ".format(INFO) +
                  "can proceed to the next step")
        else:
            print("{}This test instance is invalid although ".format(ERRO) +
                  "all network tests passed. You cannot move to the " +
                  "next step")
    else:
        print("{}Not all network tests passed. You cannot ".format(ERRO) +
              "move to the next step")
    print('')
    return err_cnt


def main():
    """
    Params:
    Returns:
        0 if succeeded.
        !0 if hit error.
        exit if hit certain error.
    """
    files = [HOST_FL,
             DEPE_PKG,
             NSDTOOL,
             'nsdperf.C',
             'makefile',]
    check_files_are_readable(files)

    fping_count, ttime_per_inst, test_thread, para_conn, buff_size, \
    socket_size, is_hosts_input, host_kv, rdma_test, rdma_ports, \
    no_rpm_check, save_hosts = parse_arguments()

    if not is_hosts_input:
        host_kv = load_json(HOST_FL)
        if host_kv is None:
            print("{0}Please populate {1} with hosts ".format(ERRO, HOST_FL) +
                  "or use '--hosts' option to specify hosts")
            sys.exit("{}Bye!\n".format(QUIT))

    hosts = []
    try:
        hosts = list(host_kv.keys())
    except BaseException as e:
        print("{}Tried to extract hosts but hit ".format(ERRO) +
              "exception: {}".format(e))
        sys.exit("{}Bye!\n".format(QUIT))
    if not hosts:
        print("{}Failed to get valid hosts".format(ERRO))
        sys.exit("{}Bye!\n".format(QUIT))

    rc = are_hosts_ipv4(hosts)
    if rc != 0:
        print("{0}Not all hosts are valid IPv4".format(ERRO, hosts))
        sys.exit("{}Bye!\n".format(QUIT))

    show_header(VERSION, fping_count, ttime_per_inst, test_thread,
                para_conn, buff_size, socket_size)
    estimate_runtime(hosts, fping_count, ttime_per_inst)

    print('')
    while True:
        print("Type 'y' to continue, 'n' to stop")
        try:
            ori_choice = input("Continue? <y/n>: ")
        except KeyboardInterrupt as e:
            print("\n{0}Hit KeyboardInterrupt".format(ERRO))
            sys.exit("{}Bye!\n".format(QUIT))
        choice = ori_choice.lower()
        if choice == 'y':
            print('')
            break
        if choice == 'n':
            print('')
            print("{0}You have typed '{1}'".format(INFO, ori_choice))
            sys.exit("{}Bye!\n".format(QUIT))

    if save_hosts:
        rc = dump_json(host_kv, HOST_FL)
        if rc != 0:
            sys.exit("{}Bye!\n".format(QUIT))

    check_localhost_is_in_hosts(hosts)

    check_passwordless_ssh(hosts)

    if no_rpm_check is True:
        print("{}RPM package check has been ignored".format(WARN))
    else:
        hs_type = ''
        if rdma_test is True:
            hs_type = 'rdma'
        pkg_kv = load_json(DEPE_PKG)
        if pkg_kv is None:
            sys.exit("{}Bye!\n".format(QUIT))
        try:
            json_ver = pkg_kv['Version']
        except KeyError as e:
            print("{0}Tried to get file version of {1} ".format(ERRO,
                  DEPE_PKG) + "but hit KeyError: {}".format(e))
            sys.exit("{}Bye!\n".format(QUIT))
        print("{}Check if required package is available ".format(INFO) +
              "according to {0} with version {1}".format(DEPE_PKG,
              json_ver))
        check_package_on_host(hosts, pkg_kv, hs_type)

    check_firewalld_service(hosts)
    check_tcp_port(hosts, 6668)
    print('')

    mlx_port_csv = []
    if rdma_test is True:
        mlx_port_csv = get_rdma_mlx_ports(hosts, rdma_ports)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    logdir = create_local_log_dir(timestamp)
    rmt_logdir = remotely_create_log_dir(hosts, timestamp)

    fping_out_kv = run_fping_test(hosts, logdir, fping_count)
    nsdperf_out_kv = run_nsdperf_test(
                         hosts,
                         logdir,
                         ttime_per_inst,
                         test_thread,
                         para_conn,
                         buff_size,
                         socket_size,
                         rdma_test,
                         mlx_port_csv)

    # Load results
    all_fping_avg_lat_kv, all_fping_max_lat_kv, all_fping_min_lat_kv, \
    all_fping_stddev_kv = load_fping_test_result(fping_out_kv)

    o2m_thrput_kv, o2m_lat_kv, o2m_lat_stddev_kv, o2m_rxe_kv, o2m_txe_kv, \
    o2m_retr_kv, o2m_avg_thrput, o2m_max_thrput, o2m_min_thrput, \
    o2m_thrput_stddev, o2m_thrput_diff_pct, m2m_thrput, m2m_lat, \
    m2m_lat_stddev, m2m_rxe_kv, m2m_txe_kv, m2m_retr_kv = \
        load_nsdperf_test_result(nsdperf_out_kv)

    # Compare againsts KPIs
    all_avg_fping_errors = check_fping_kpi(
                               all_fping_avg_lat_kv,
                               all_fping_max_lat_kv,
                               all_fping_min_lat_kv,
                               all_fping_stddev_kv,
                               "1:n",
                               rdma_test)

    all_nsd_errors = check_nsd_kpi(
                         o2m_thrput_kv,
                         o2m_avg_thrput,
                         o2m_max_thrput,
                         o2m_min_thrput,
                         o2m_thrput_stddev,
                         o2m_thrput_diff_pct,
                         o2m_lat_kv,
                         o2m_lat_stddev_kv,
                         o2m_rxe_kv,
                         o2m_txe_kv,
                         o2m_retr_kv,
                         m2m_thrput,
                         m2m_lat,
                         m2m_lat_stddev,
                         m2m_rxe_kv,
                         m2m_txe_kv,
                         m2m_retr_kv)

    save_throughput_to_csv(logdir, o2m_thrput_kv, m2m_thrput)

    acceptance_flag = check_parameters(
                          fping_count,
                          ttime_per_inst,
                          test_thread,
                          para_conn,
                          buff_size,
                          socket_size)

    rc = print_end_summary(
             all_avg_fping_errors,
             all_nsd_errors,
             acceptance_flag)
    return rc


if __name__ == '__main__':
    sys.exit(main())

