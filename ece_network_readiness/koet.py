#!/usr/bin/python
import json
import os
import sys
import socket
import datetime
import subprocess
import platform
import shlex
import time
from shutil import copyfile
from decimal import Decimal
import argparse
import operator
from math import sqrt, ceil
from functools import reduce
import re
import csv

# This script version, independent from the JSON versions
VERSION = "1.21"

# Colorful constants
RED = '\033[91m'
BOLDRED = '\033[91;1m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
PURPLE = '\033[35m'
GOLDEN = '\033[33m'
BOLDGOLDEN = '\033[33;1m'
NOCOLOR = '\033[0m'

INFO = "{0}INFO:{1} ".format(GREEN, NOCOLOR)
WARN = "{0}WARNING: {1}".format(YELLOW, NOCOLOR)
ERRO = "{0}FATAL:{1} ".format(RED, NOCOLOR)
QUIT = "{0}QUIT: {1}".format(RED, NOCOLOR)

# KPI and acceptance values
KPI_AVG_LATENCY = 1.00 # 1 msec or less
KPI_MAX_LATENCY = 2.00
KPI_STDDEV_LTNC = KPI_AVG_LATENCY / 3.0
KPI_NSD_THROUGH = 2000 # 2000 MB/s or more, with lots of margin
ACC_FPING_COUNT = 500 # 500 or more
ACC_TESTER_THRE = 32 # fixed 32
ACC_BUFFER_SIZE = 2 * 1024 * 1024 # fixed 2M
ACC_TTIME = 1200 # 1200 or more

# TODO Move following global variables to json file
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

NSDPERF = "nsdperfTool.py"

# IP RE
IPPATT = re.compile('.*inet\s+(?P<ip>.*)\/\d+')

# devnull redirect destination
DEVNULL = open(os.devnull, 'w')

try:
    raw_input      # Python 2
    PYTHON3 = False
except NameError:  # Python 3
    raw_input = input
    PYTHON3 = True

if PYTHON3:
    import statistics
    try:
        import distro
    except ImportError:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot import distro. Check python3-distro is installed\n")


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


def write_json_file_from_dictionary(hosts_dictionary, json_file_str):
    # We are going to generate or overwrite the hosts JSON file
    try:
        with open(json_file_str, "w") as json_file:
            json.dump(hosts_dictionary, json_file)
            print(GREEN + "OK: " + NOCOLOR + "JSON file: " + json_file_str +
                  " [over]written")

    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot write JSON file: " + json_file_str)


def check_localnode_is_in(hosts_dictionary):
    localNode = None
    try:
        raw_out = os.popen("ip addr show").read()
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR + "cannot list ip " +
                 "address on local node\n")
    # create a list of allip addresses for local node
    iplist = IPPATT.findall(raw_out)

    # check for match with one of input ip addresses
    for node in hosts_dictionary.keys():
        if node in iplist:
            localNode = node
            break
    if localNode is None:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Local node is not part of the test\n")


def estimate_runtime(hosts_dictionary, fp_count, ttime_per_inst):
    number_of_hosts = len(hosts_dictionary)
    estimated_rt_fp = number_of_hosts * fp_count
    # use number of hosts + 1 to include N:N iteration of nsdperf
    # add 20 sec per node as startup, shutdown, compile overhead
    estimated_rt_perf = (number_of_hosts + 1) * (20 + ttime_per_inst)
    estimated_runtime = estimated_rt_fp + estimated_rt_perf
    # minutes we always return 2 even for short test runs
    estimated_runtime_minutes = int(ceil(estimated_runtime / 60.))
    return max(estimated_runtime_minutes, 2)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--hosts',
        action='store',
        dest='hosts',
        help='IPv4 addresses in CSV format. E.g., IP0,IP1,IP2,IP3',
        metavar='HOSTS_CSV',
        type=str,
        default="")
    parser.add_argument(
        '-s',
        '--save-hosts',
        action='store_true',
        dest='save_hosts',
        help='[Over]write hosts.json with IP addresses that passed ' +
        'the check and followed option: --hosts',
        default=False)
    parser.add_argument(
        '-c',
        '--fping-count',
        action='store',
        dest='fping_count',
        help='count of request packets to send to each target. The ' +
        'minimum value can be set to {} packets for quick '.format(
        MIN_FPING_COUNT) + 'test. For certification, it is at ' +
        'least {} '.format(ACC_FPING_COUNT) + 'packets',
        metavar='COUNT',
        type=int,
        default=500)
    parser.add_argument(
        '-t',
        '--ttime-per-instance',
        action='store',
        dest='ttime_per_inst',
        help='test time per nsdperf instance with unit sec. The ' +
        'minimum value can be set to 10 sec for quick test. For ' +
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
        'The minimum value is 1 and the maximum value is {}. '.format(
        MAX_TESTERS) + 'For certification, it is {}'.format(
        ACC_TESTER_THRE),
        metavar='THREAD',
        type=int,
        default=ACC_TESTER_THRE)
    parser.add_argument(
        '-p',
        '--parallel',
        action='store',
        dest='para_conn',
        help='parallel socket connections of nsdperf per instance. ' +
        'The minimum value is 1 and the maximum value is {}. '.format(
        MAX_PARALLEL) + 'Default value is {}'.format(DEF_PARALLEL),
        metavar='PARALLEL',
        type=int,
        default=DEF_PARALLEL)
    parser.add_argument(
        '-b',
        '--buffer-size',
        action='store',
        dest='buff_size',
        help='buffer size for each I/O of nsdperf with unit bytes. The ' +
        'minimum value is {0} bytes and the maximum value is {1} '.format(
        MIN_BUFFSIZE, MAX_BUFFSIZE) + 'bytes. For certification, it is ' +
        '{} bytes'.format(ACC_BUFFER_SIZE),
        metavar='BUFFSIZE',
        type=int,
        default=ACC_BUFFER_SIZE)
    parser.add_argument(
        '-o',
        '--socket-size',
        action='store',
        dest='socket_size',
        help='maximum TCP socket send and receive buffer size with ' +
        'unit bytes. 0 means the system default setting and the ' +
        'maximum value is {} bytes. This tool would set the '.format(
        MAX_SOCKSIZE) + 'socket size to the I/O buffer size if socket ' +
        'size was not specified explicitly',
        metavar='SOCKSIZE',
        type=int,
        default=ACC_BUFFER_SIZE)
    parser.add_argument(
        '--rdma',
        action='store',
        dest='rdma',
        help='Enable RDMA check and assign ports in CSV format. E.g., ' +
        'ib0,ib1. Use logical device name rather than mlx name',
        metavar='PORTS_CSV',
        default="")
    parser.add_argument(
        '--roce',
        action='store',
        dest='roce',
        help='Enable RoCE check and assign ports in CSV format. E.g., ' +
        'eth0,eth1. Use logical device name',
        metavar='PORTS_CSV',
        default="")
    parser.add_argument(
        '--rpm-check-disabled',
        action='store_true',
        dest='no_rpm_check',
        help='Disable dependent rpm package check. Use this option ' +
        'only if you are sure that all dependent packages have been ' +
        'installed',
        default=False)

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='Network Readiness {}\n'.format(VERSION))

    args = parser.parse_args()

    if args.fping_count < 2:
        sys.exit("{}fping count cannot be less than 2\n".format(QUIT))
    if args.ttime_per_inst < 10:
        sys.exit("{}nsdperf test time cannot be less ".format(QUIT) +
                 "than 10 sec\n")
    if args.test_thread < 1 or args.test_thread > MAX_TESTERS:
        sys.exit("{}nsdperf test threads are out of ".format(QUIT) +
                 "range\n")
    if args.para_conn < 1 or args.para_conn > MAX_PARALLEL:
        sys.exit("{}nsdperf parallel connection is out ".format(QUIT) +
                 "of range\n")
    if args.buff_size < MIN_BUFFSIZE or args.buff_size > MAX_BUFFSIZE:
        sys.exit("{}nsdperf buffer size is out of range\n".format(QUIT))
    if args.socket_size < 0 or args.socket_size > MAX_SOCKSIZE:
        sys.exit("{}nsdperf socket size is out of range\n".format(QUIT))

    if 'mlx' in args.rdma:
        sys.exit("{}RDMA ports must be OS names ".format(QUIT) +
                 "(ib0,ib1,...)\n")
    if 'mlx' in args.roce:
        sys.exit("{}RoCE ports must be OS names ".format(QUIT) +
                 "(ib0,ib1,...)\n")
    # we check is a CSV string and if so we put it on dictionary
    cli_hosts = False
    hosts_dictionary = {}
    if args.hosts != "":
        cli_hosts = True
        try:
            host_raw = args.hosts
            hosts = host_raw.split(",")
            for host_key in hosts:
                hosts_dictionary.update({host_key: "ECE"})
        except Exception:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "hosts parameter is not on CSV format")

    rdma_ports_list = []
    if args.rdma != "":
        rdma_test = True
        rdma_ports_raw = args.rdma
        try:
            rdma_ports_list = rdma_ports_raw.split(",")
        except Exception:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "rdma parameter is not on CSV format")
    else:
        rdma_test = False
    if args.save_hosts and not cli_hosts:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot generate hosts file if hosts not passed with --hosts")


    roce_ports_list = []
    if args.roce != "":
        if platform.processor() != 's390x':
            sys.exit(RED + "QUIT: " + NOCOLOR +
                 "RoCE is only supported on s390x" )
        roce_test = True
        roce_ports_raw = args.roce
        try:
            roce_ports_list = roce_ports_raw.split(",")
        except Exception:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "roce parameter is not on CSV format")
    else:
        roce_test = False
    if args.save_hosts and not cli_hosts:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot generate hosts file if hosts not passed with --hosts")


    return (args.fping_count, args.ttime_per_inst, args.test_thread,
            args.para_conn, args.buff_size, args.socket_size, cli_hosts,
            hosts_dictionary, rdma_test, rdma_ports_list, roce_test,
            roce_ports_list, args.no_rpm_check, args.save_hosts)


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
        buffer_size and buffer_size == ACC_BUFFER_SIZE and \
        socket_size and socket_size >= buffer_size:
        acceptance_flag = True
    return acceptance_flag


def show_header(
        module_version,
        json_version,
        estimated_runtime_str,
        fping_count,
        ttime_per_inst,
        thread_num,
        para_conn,
        buffer_size,
        socket_size):
    # Say hello and give chance to disagree
    while True:
        print("")
        print("Welcome to Network Readiness {}".format(module_version))
        print("")
        print("The purpose of the tool is to obtain network metrics of a " +
              "number of nodes then compare them with certain KPIs")
        print("Please access to {} to get required versions ".format(GIT_URL) +
              "and report issues if necessary")
        print("")
        print("{0}Prerequisite:{1}".format(BOLDGOLDEN, NOCOLOR))
        print("{}  Remote root passwordless ssh between all ".format(GOLDEN) +
              "all nodes must be configured{}".format(NOCOLOR))
        print("")
        print("{0}NOTE:{1}".format(BOLDRED, NOCOLOR))
        print("{}  This tool comes with absolutely no warranty ".format(RED) +
              "of any kind. Use it at your own risk.{}".format(NOCOLOR))
        print("{}  The latency and throughput numbers shown ".format(RED) +
              "by this tool are under special parameters. That is not a " +
              "generic storage standard.{}".format(NOCOLOR))
        print("{}  The numbers do not reflect any specification ".format(RED) +
              "of IBM Storage Scale or any user workload's performance " +
              "number that run on it.{}".format(NOCOLOR))
        print("")
        print("JSON files versions:")
        print("    supported OS:     {}".format(json_version['supported_OS']))
        print("    packages:         {}".format(json_version['packages']))
        print("    packages RDMA:    {}".format(json_version['packages_rdma']))
        print("    packages RoCE:    {}".format(json_version['packages_roce']))
        print("")
        print("{0}To certify the environment:{1}".format(GREEN, NOCOLOR))
        print("{0}The average latency KPI is {1} msec{2}".format(GREEN,
              KPI_AVG_LATENCY, NOCOLOR))
        print("{0}The maximum latency KPI is {1} mesc{2}".format(GREEN,
              KPI_MAX_LATENCY, NOCOLOR))
        kpi_lat_stddev = "{:.2f}".format(KPI_STDDEV_LTNC)
        print("{0}The standard deviation latency KPI is {1} mesc{2}".format(
              GREEN, kpi_lat_stddev, NOCOLOR))
        print("{0}The throughput KPI is {1} MB/sec{2}".format(GREEN,
              KPI_NSD_THROUGH, NOCOLOR))
        print("")
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
        if buffer_size and buffer_size == ACC_BUFFER_SIZE:
            if socket_size < buffer_size:
                print("{0}{1} bytes nsdperf socket size is less ".format(WARN,
                      socket_size) + "than {} bytes buffer size".format(
                      buffer_size))
            else:
                print("{0}The nsdperf needs {1} bytes buffer size. ".format(
                      INFO, ACC_BUFFER_SIZE) + "Current setting is " +
                      "{} bytes".format(buffer_size))
        else:
            print("{0}The nsdperf needs {1} bytes buffer size. ".format(WARN,
                  ACC_BUFFER_SIZE) + "Current setting is {} bytes".format(
                  buffer_size))
        print("")
        print("{}The total time consumption according to above ".format(INFO) +
              "paramters is {0}~{1} minutes{2}".format(PURPLE,
              estimated_runtime_str, NOCOLOR))
        print("")
        run_this = raw_input("Do you want to continue? (y/n): ")
        if run_this.lower() == 'y':
            break
        if run_this.lower() == 'n':
            print
            sys.exit("{}Have a nice day! Bye.\n".format(QUIT))
    print("")


def check_os_redhat(os_dictionary):
    redhat8 = False
    # Check redhat-release vs dictionary list
    try:
      redhat_distribution = platform.linux_distribution()
    except AttributeError as E:
        import distro
        redhat_distribution = distro.linux_distribution()

    redhat_distribution_str = redhat_distribution[0] + \
        " " + redhat_distribution[1]
    error_message = RED + "QUIT: " + NOCOLOR + " " + \
        redhat_distribution_str + " is not a supported OS for this tool\n"
    try:
        if os_dictionary[redhat_distribution_str] == 'OK':
            #print(GREEN + "OK: " + NOCOLOR + redhat_distribution_str +
            #      " is a supported OS for this tool")
            #print("")
            if "8." in redhat_distribution[1]:
                redhat8 = True
        else:
            sys.exit(error_message)
    except Exception:
        sys.exit(error_message)
    return redhat8


def get_json_versions(
                    os_dictionary,
                    packages_dictionary,
                    packages_roce_dict,
                    packages_rdma_dict):
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

    try:
        json_version['packages_rdma'] = packages_rdma_dict['json_version']
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Cannot load version from packages RDMA JSON")

    if packages_roce_dict is not None:
        try:
            json_version['packages_roce'] = packages_roce_dict['json_version']
        except Exception:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "Cannot load version from packages RoCE JSON")
    else:
        json_version['packages_roce'] = "N/A"


    # If we made it this far lets return the dictionary. This was being stored
    # in its own file before
    return json_version


def check_distribution():
    # Decide if this is a redhat or a CentOS. We only checking the running
    # node, that might be a problem
    if PYTHON3:
        what_dist = distro.distro_release_info()['id']
    else:
        what_dist = platform.dist()[0]
    if what_dist == "redhat" or "centos":
        return what_dist
    else:  # everything esle we fail
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "this only runs on RedHat at this moment")


def ssh_rpm_is_installed(host, rpm_package):
    # returns the RC of rpm -q rpm_package or quits if it cannot run rpm
    errors = 0
    try:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'rpm',
                                       '-q',
                                       rpm_package],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot run rpm over ssh on host " + host)
    return return_code


def ssh_service_is_up(host, service_name):
    try:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'systemctl',
                                       'is-active',
                                       '--quiet',
                                       service_name],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot run systemctl over ssh on host " + host)
    if return_code == 0:
        service_is_up = True
    else:
        service_is_up = False

    return service_is_up


def firewalld_check(hosts_dictionary):
    # Checks if if firewalld is up on any node
    errors = 0
    for host in hosts_dictionary.keys():
        firewalld_is_up = ssh_service_is_up(host, "firewalld")
        if firewalld_is_up:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "on host " +
                host +
                " the firewalld service is running")
            errors = errors + 1
        else:
            print(
                 GREEN +
                 "OK: " +
                 NOCOLOR +
                 "on host " +
                 host +
                 " the firewalld service is not running" )
    if errors > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the firewalld status before running this tool again.\n")


def check_tcp_port_free(hosts_dictionary, tcpport):
    errors = 0
    # Checks certain port is not in use
    for host in hosts_dictionary.keys():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        openit = sock.connect_ex((host, tcpport))
        if openit == 0:  # I can connect so it is NOT free
            errors = errors + 1
            print(RED +
                  "ERROR: " +
                  NOCOLOR +
                  "on host " +
                  str(host) +
                  " TCP port " +
                  str(tcpport) +
                  " seems to be not free")
        else:  # cannot connect so not in used or not accesible
            print(
                GREEN +
                "OK: " +
                NOCOLOR +
                "on host " +
                str(host) +
                " TCP port " +
                str(tcpport) +
                " seems to be free")

    if errors > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "TCP port " + str(tcpport) + " is not free in all hosts")


def check_permission_files():
    #Check executable bits and read bits for files
    readable_files=["hosts.json", "makefile", "nsdperf.C", "packages.json",
                    "packages_rdma.json", "packages_rdma_rh8.json",
                    "packages_roce_rh8.json", "supported_OS.json"]
    executable_files=["nsdperfTool.py"]

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


def host_packages_check(hosts_dictionary, packages_dictionary):
    # Checks if packages from JSON are installed or not based on the input
    # data ont eh JSON
    errors = 0
    for host in hosts_dictionary.keys():
        for rpm_package in packages_dictionary.keys():
            if rpm_package != "json_version":
                current_package_rc = ssh_rpm_is_installed(host, rpm_package)
                expected_package_rc = packages_dictionary[rpm_package]
                if current_package_rc == expected_package_rc:
                    print(
                        GREEN +
                        "OK: " +
                        NOCOLOR +
                        "on host " +
                        host +
                        " the " +
                        rpm_package +
                        " installation status is as expected")
                else:
                    print(
                        RED +
                        "ERROR: " +
                        NOCOLOR +
                        "on host " +
                        host +
                        " the " +
                        rpm_package +
                        " installation status is *NOT* as expected")
                    errors = errors + 1
    if errors > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the packages before running this tool again.\n")


def ssh_file_exists(host, fileurl):
    # returns the RC of ssh+ls of a file or quits if any error
    try:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'which',
                                       fileurl],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot run ls over ssh on host " + host)
    return return_code

# Will be used for RoCE too
def ssh_rdma_ports_are_up(host, rdma_ports_list):
    errors = 0
    for port in rdma_ports_list:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'ibdev2netdev',
                                       '|',
                                       'grep',
                                       port,
                                       '|',
                                       'grep',
                                       '"(Up)"'],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
        if return_code == 0:
            print(
                GREEN +
                "OK: " +
                NOCOLOR +
                "on host " +
                host +
                " the RDMA port " +
                port +
                " is on UP state")
        else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "on host " +
                host +
                " the RDMA port " +
                port +
                " is *NOT* on UP state")
            errors = errors + 1
    if errors == 0:
        all_ports_up = True
    else:
        all_ports_up = False
    return all_ports_up


def ssh_roce_ports_are_up(host, roce_ports_list):
    errors = 0
    for port in roce_ports_list:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'ibdev2netdev',
                                       '|',
                                       'grep',
                                       port,
                                       '|',
                                       'grep',
                                       '"(Up)"'],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
        if return_code == 0:
            print(
                GREEN +
                "OK: " +
                NOCOLOR +
                "on host " +
                host +
                " the RoCE port " +
                port +
                " is on UP state")
        else:
            print(
                RED +
                "ERROR: " +
                NOCOLOR +
                "on host " +
                host +
                " the RoCE port " +
                port +
                " is *NOT* on UP state")
            errors = errors + 1
    if errors == 0:
        all_ports_up = True
    else:
        all_ports_up = False
    return all_ports_up


def check_rdma_port_mode(hosts_ports_dict):
    errors = 0
    for host in hosts_ports_dict.keys():
        ssh_command = ('ssh -o StrictHostKeyChecking=no ' +
                       '-o LogLevel=error ' + host + ' ')
        # we remove the port bit
        for port in hosts_ports_dict[host].keys():
            card_str = str(hosts_ports_dict[host][port].split('/')[0])
            try:
                raw_out = os.popen(
                                ssh_command + '/usr/sbin/ibstat ' +
                                card_str).read()
            except BaseException:
                sys.exit(RED + "QUIT: " + NOCOLOR +
                         "There was an issue to query rdma ports on "
                         + host + "\n")
            if 'Ethernet' in raw_out:
                print(
                    RED +
                    "ERROR: " +
                    NOCOLOR +
                    "host " +
                    host +
                    " has Mellanox ports " +
                    port +
                    " on Ethernet mode")
                errors = errors + 1
            else:
                 print(
                    GREEN +
                    "OK: " +
                    NOCOLOR +
                    "on host " +
                    host +
                    " Mellanox ports  " +
                    port +
                    " on Ethernet mode are supported")
    return errors


def check_roce_port_mode(hosts_ports_dict):
    errors = 0
    for host in hosts_ports_dict.keys():
        ssh_command = ('ssh -o StrictHostKeyChecking=no ' +
                       '-o LogLevel=error ' + host + ' ')
        # we remove the port bit
        for port in hosts_ports_dict[host].keys():
            card_str = str(hosts_ports_dict[host][port].split('/')[0])
            try:
                raw_out = os.popen(
                                ssh_command + '/usr/sbin/ibstat ' +
                                card_str).read()
            except BaseException:
                sys.exit(RED + "QUIT: " + NOCOLOR +
                         "There was an issue to query roce ports on "
                         + host + "\n")

    return errors


def  map_ib_to_mlx_roce(host, roce_ports_list):
    port_pair_dict = {}
    ssh_command = ('ssh -o StrictHostKeyChecking=no ' +
                   '-o LogLevel=error ' + host + ' ')
    try:
        raw_os = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$5}'").read()
        raw_mlx = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$1}'").read()
        raw_port = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$3}'").read()
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "There was an issue to query rdma/roce cards on " + host + "\n")
    raw_list_os = raw_os.strip().split("\n")
    raw_list_mlx = raw_mlx.strip().split("\n")
    raw_list_port = raw_port.strip().split("\n")

    port_pair_dict = {osdev: '{}/{}'.format(raw_list_mlx[osidx],raw_list_port[osidx])


    for osidx, osdev in
        enumerate(raw_list_os) if osdev in roce_ports_list}


    for osdev in port_pair_dict:
        print(
              GREEN +
              "OK: " +
              NOCOLOR +
              "on host " +
              host +
              " the RoCE port " +
              osdev +
              " is CA " +
              port_pair_dict[osdev])
    return port_pair_dict


def  map_ib_to_mlx_rdma(host, rdma_ports_list):
    port_pair_dict = {}
    ssh_command = ('ssh -o StrictHostKeyChecking=no ' +
                   '-o LogLevel=error ' + host + ' ')
    try:
        raw_os = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$5}'").read()
        raw_mlx = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$1}'").read()
        raw_port = os.popen(
                        ssh_command +
                        "ibdev2netdev|awk '{print$3}'").read()
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "There was an issue to query rdma/roce cards on " + host + "\n")
    raw_list_os = raw_os.strip().split("\n")
    raw_list_mlx = raw_mlx.strip().split("\n")
    raw_list_port = raw_port.strip().split("\n")

    port_pair_dict = {osdev: '{}/{}'.format(raw_list_mlx[osidx],raw_list_port[osidx])


    for osidx, osdev in
        enumerate(raw_list_os) if osdev in rdma_ports_list}


    for osdev in port_pair_dict:
        print(
              GREEN +
              "OK: " +
              NOCOLOR +
              "on host " +
              host +
              " the RDMA port " +
              osdev +
              " is CA " +
              port_pair_dict[osdev])
    return port_pair_dict


def check_rdma_ports_OS(host, port):
    # Lets check we have the tool we need
    try:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'ifconfig',
                                       port],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot check port over ssh on host " + host)
    if return_code == 0:
        error = False
    else:
        error = True
    return error

def check_roce_ports_OS(host, port):
    # Lets check we have the tool we need
    try:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'ifconfig',
                                       port],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot check port over ssh on host " + host)
    if return_code == 0:
        error = False
    else:
        error = True
    return error


def check_rdma_tools(host, toolpath):
    # Given the host returns a list of the IB ports on up status
    errors = 0
    # Lets check we have the tool we need
    rc_tool = ssh_file_exists(host, toolpath)
    if rc_tool == 0:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "on host " +
            host +
            " the file " +
            toolpath +
            " exists")
    else:
        print(
            RED +
            "ERROR: " +
            NOCOLOR +
            "on host " +
            host +
            " the file " +
            toolpath +
            " does *NOT* exists")
        errors = errors + 1
    return errors


def check_roce_tools(host, toolpath):
    # Given the host returns a list of the IB ports on up status
    errors = 0
    # Lets check we have the tool we need
    rc_tool = ssh_file_exists(host, toolpath)
    if rc_tool == 0:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "on host " +
            host +
            " the file " +
            toolpath +
            " exists")
    else:
        print(
            RED +
            "ERROR: " +
            NOCOLOR +
            "on host " +
            host +
            " the file " +
            toolpath +
            " does *NOT* exists")
        errors = errors + 1
    return errors


def unique_items_list(my_list):
    unique_items_list = []
    for item in my_list:
        if item not in unique_items_list:
            unique_items_list.append(item)
    return unique_items_list


def create_rdma_mlx_csv(hosts_ports_dict, rdma_ports_list):
    mlx_list = []
    for host in hosts_ports_dict.keys():
        for os_port in hosts_ports_dict[host].keys():
            if os_port in rdma_ports_list:
                mlx_list.append(hosts_ports_dict[host][os_port])

    # so we have a list with mlx ports
    mlx_list_unique = unique_items_list(mlx_list)
    mlx_list_unique_csv = ','.join(mlx_list_unique)
    return mlx_list_unique_csv


def create_roce_mlx_csv(hosts_ports_dict, roce_ports_list):
    mlx_list = []
    for host in hosts_ports_dict.keys():
        for os_port in hosts_ports_dict[host].keys():
            if os_port in roce_ports_list:
                mlx_list.append(hosts_ports_dict[host][os_port])

    # so we have a list with mlx ports
    mlx_list_unique = unique_items_list(mlx_list)
    mlx_list_unique_csv = ','.join(mlx_list_unique)
    return mlx_list_unique_csv


def check_rdma_ports(hosts_dictionary, rdma_ports_list):
    errors_tool = 0
    fatal_error = False
    for host in hosts_dictionary.keys():
        ibdev2netdev_filepath = "ibdev2netdev"
        error_tool_ibdev = check_rdma_tools(host, ibdev2netdev_filepath)
        ibstat_filepath = "ibstat"
        error_tool_ibstat = check_rdma_tools(host, ibstat_filepath)
    errors_tool = error_tool_ibdev + error_tool_ibstat
    if errors_tool > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the missing files before running this tool again.\n")
    # Lets see if does exist on the node or hard fail
    not_OS_port = False
    for host in hosts_dictionary.keys():
        for port in rdma_ports_list:
            not_OS_port = check_rdma_ports_OS(host, port)
            if not_OS_port:
                sys.exit(RED + "QUIT: " + NOCOLOR + "On host " +
                         str(host) + " port " + port + " not found\n")
    # Lets check the ports are UP on all nodes, or fail
    errors_ports = 0
    errors_port_mode = 0
    for host in hosts_dictionary.keys():
        ports_are_up = ssh_rdma_ports_are_up(host, rdma_ports_list)
        if not ports_are_up:
            errors_ports = errors_ports + 1
    if errors_ports > 0:
        fatal_error = True
    hosts_ports_dict = {}
    for host in hosts_dictionary.keys():
        hosts_ports_dict[host] = map_ib_to_mlx_rdma(host, rdma_ports_list)
    # Create list of mlx ports
    rdma_ports_csv_mlx = create_rdma_mlx_csv(hosts_ports_dict, rdma_ports_list)
    # Check Ethernet mode and status UP
    errors_port_mode = check_rdma_port_mode(hosts_ports_dict)
    if errors_port_mode > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the port mode or disconnect the link " +
                 "before running this tool again.\n")
    return fatal_error, rdma_ports_csv_mlx


def check_roce_ports(hosts_dictionary, roce_ports_list):
    errors_tool = 0
    fatal_error = False
    for host in hosts_dictionary.keys():
        ibdev2netdev_filepath = "ibdev2netdev"
        error_tool_ibdev = check_roce_tools(host, ibdev2netdev_filepath)
        ibstat_filepath = "ibstat"
        error_tool_ibstat = check_roce_tools(host, ibstat_filepath)
    errors_tool = error_tool_ibdev + error_tool_ibstat
    if errors_tool > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the missing files before running this tool again.\n")
    # Lets see if does exist on the node or hard fail
    not_OS_port = False
    for host in hosts_dictionary.keys():
        for port in roce_ports_list:
            not_OS_port = check_roce_ports_OS(host, port)
            if not_OS_port:
                sys.exit(RED + "QUIT: " + NOCOLOR + "On host " +
                         str(host) + " port " + port + " not found\n")
    # Lets check the ports are UP on all nodes, or fail
    errors_ports = 0
    errors_port_mode = 0
    for host in hosts_dictionary.keys():
        ports_are_up = ssh_roce_ports_are_up(host, roce_ports_list)
        if not ports_are_up:
            errors_ports = errors_ports + 1
    if errors_ports > 0:
        fatal_error = True
    hosts_ports_dict = {}
    for host in hosts_dictionary.keys():
        hosts_ports_dict[host] = map_ib_to_mlx_roce(host, roce_ports_list)
    # Create list of mlx ports
    roce_ports_csv_mlx = create_roce_mlx_csv(hosts_ports_dict, roce_ports_list)
    # Check Ethernet mode and status UP
    errors_port_mode = check_roce_port_mode(hosts_ports_dict)
    if errors_port_mode > 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Fix the port mode or disconnect the link " +
                 "before running this tool again.\n")
    return fatal_error, roce_ports_csv_mlx


def is_IP_address(ip):
    # Lets check is a full ip by counting dots
    if ip.count('.') != 3:
        return False
    try:
        socket.inet_aton(ip)
        return True
    except Exception:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot check IP address " + ip + "\n")


def check_hosts_are_ips(hosts_dictionary):
    for host in hosts_dictionary.keys():
        is_IP = is_IP_address(host)
        if not is_IP:
            sys.exit(
                RED +
                "QUIT: " +
                NOCOLOR +
                "on hosts JSON file or CLI parameter '" +
                host +
                "' is not a valid IPv4. Fix before running this tool again.\n")


def check_hosts_number(hosts_dictionary):
    number_unique_hosts = len(hosts_dictionary)
    number_unique_hosts_str = str(number_unique_hosts)
    if len(hosts_dictionary) > 64 or len(hosts_dictionary) < 2:
        sys.exit(
            RED +
            "QUIT: " +
            NOCOLOR +
            "the number of hosts is not valid. It is " +
            number_unique_hosts_str +
            " and should be between 2 and 64 unique hosts.\n")


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


def create_log_dir(hosts_dictionary, log_dir_timestamp):
    # datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    print ("Creating log dir on hosts:")
    errors = 0
    logdir = os.path.join(
        os.getcwd(),
        'log',
        log_dir_timestamp)
    for host in hosts_dictionary:
        return_code = subprocess.call(['ssh',
                                       '-o',
                                       'StrictHostKeyChecking=no',
                                       '-o',
                                       'LogLevel=error',
                                       host,
                                       'mkdir',
                                       '-p',
                                       logdir],
                                      stdout=DEVNULL,
                                      stderr=DEVNULL)
        if return_code == 0:
            print(
                GREEN +
                "OK: " +
                NOCOLOR +
                "on host " +
                host +
                " logdir " +
                logdir +
                " has been created")
        else:
            print(
                  RED +
                  "ERROR: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " logdir " +
                  logdir +
                  " has *NOT* been created")
            errors = errors + 1
    if errors > 0:
        sys.exit(RED +
                 "QUIT: " +
                 NOCOLOR +
                 "we cannot continue without all the log directories created")
    else:
        return logdir


def latency_test(hosts_dictionary, logdir, fping_count):
    fping_count_str = str(fping_count)
    hosts_fping = ""
    for host in sorted(hosts_dictionary.keys()):  # we ping ourselvels as well
        hosts_fping = hosts_fping + host + " "

    for srchost in sorted(hosts_dictionary.keys()):
        print("")
        print("Starting ping run from " + srchost + " to all nodes")
        fileurl = os.path.join(logdir, "lat_" + srchost + "_" + "all")
        command = "ssh -o StrictHostKeyChecking=no -o LogLevel=error " + \
                  str(srchost) + " fping -C " + fping_count_str + \
                  " -q -A " + str(hosts_fping)
        with open(fileurl, 'wb', 0) as logfping:
            runfping = subprocess.Popen(
                           shlex.split(command),
                           stderr=subprocess.STDOUT,
                           stdout=logfping)
            runfping.wait()
            logfping.close()
        print("Ping run from " + srchost + " to all nodes completed")


def throughput_test_os(command, nsd_logfile, client):
    try:
        runperf = subprocess.Popen(shlex.split(command), stdout=nsd_logfile)
        runperf.wait()
        # Extra wait here it might be not needed now that we added it on
        # nsdperTool.py startup, but we keep it.
        time.sleep(5)
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "Throughput run " + client + " failed unexpectedly " +
                 " when calling: " + str(command) + "\n")


def throughput_test(hosts_dictionary,
                    logdir,
                    ttime_per_inst,
                    test_thread,
                    para_conn,
                    buff_size,
                    socket_size,
                    rdma_test,
                    rdma_ports_csv_mlx,
                    roce_test,
                    roce_ports_csv_mlx):
    throughput_json_files_list = []
    print("")
    print("Starting throughput tests. Please be patient.")
    for client in hosts_dictionary.keys():
        print("")
        print("Start throughput run from " + client + " to all nodes")
        server_hosts_dictionary = dict(hosts_dictionary)
        del server_hosts_dictionary[client]
        server_csv_str = (",".join(server_hosts_dictionary.keys()))
        # Craft the call of nsdperf exec/wrapper
        pre_cmd = "{0} -t read -k {1} -b {2} ".format(NSDPERF, socket_size, \
                  buff_size) + "-W {0} -T {0} -P {1} -d {2} ".format( \
                  test_thread, para_conn, logdir) + " -s {} ".format( \
                  server_csv_str) + "-c {0} -l {1}".format(client,
                  ttime_per_inst)
        command = ""
        if rdma_test:
            command = "{0} -p {1}".format(pre_cmd, rdma_ports_csv_mlx)
        elif roce_test:
            command = "{0} -p {1}".format(pre_cmd, roce_ports_csv_mlx)
        else:
            # History: nReceivers = 256, nWorkers = 256, nTesterThreads = 256
            command = pre_cmd

        nsd_logfile = open(logdir + "/nsdperfTool_log", "a")
        if PYTHON3:           
            command = "python3 {}".format(command)
        else:                 
            command = "python2 {}".format(command)
        throughput_test_os(command, nsd_logfile, client)
        nsd_logfile.close()
        # Copy the file to avoid overwrite it
        try:
            copyfile(logdir + "/nsdperfResult.json", logdir + "/nsd_" +
                     client + ".json")
        except BaseException:
            print(YELLOW + "WARNING: " + NOCOLOR +
                  "cannot copy result JSON file")
        print("Completed throughput run from " + client + " to all nodes")
    print("")
    print("Starting many to many nodes throughput test")
    # We run a mess run to catch few more issues
    middle_index = int(len(hosts_dictionary)/2)
    if PYTHON3:
        clients_nodes_d = dict(list(hosts_dictionary.items())[middle_index:])
        servers_nodes_d = dict(list(hosts_dictionary.items())[:middle_index])
    else:
        clients_nodes_d = dict(hosts_dictionary.items()[middle_index:])
        servers_nodes_d = dict(hosts_dictionary.items()[:middle_index])
    clients_csv = (",".join(clients_nodes_d.keys()))
    servers_csv = (",".join(servers_nodes_d.keys()))
    pre_cmd = "{0} -t read -k {1} -b {2} ".format(NSDPERF, socket_size, \
              buff_size) + "-W {0} -T {0} -P {1} -d {2} ".format( \
              test_thread, para_conn, logdir) + " -s {} ".format( \
              servers_csv) + "-c {0} -l {1}".format(clients_csv,
              ttime_per_inst)
    if rdma_test:
        command = "{0} -p {1}".format(pre_cmd, rdma_ports_csv_mlx)
    elif roce_test:
        command = "{0} -p {1}".format(pre_cmd, roce_ports_csv_mlx)
    else:
        # History: nReceivers = 256, nWorkers = 256, nTesterThreads = 256
        command = pre_cmd

    nsd_logfile = open(logdir + "/nsdperfTool_log", "a")
    if PYTHON3:
        command = "python3 {}".format(command)
    else:
        command = "python2 {}".format(command)
    throughput_test_os(command, nsd_logfile, client)
    nsd_logfile.close()
    # Copy the file to avoid overwrite it
    try:
        copyfile(logdir + "/nsdperfResult.json", logdir +
                 "/nsd_mess" + ".json")
    except BaseException:
        print(YELLOW + "WARNING: " + NOCOLOR +
              "cannot copy result JSON file")
    print("Completed many to many nodes throughput test")
    return clients_nodes_d


def mean_list(list):
    if len(list) == 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot calculate mean of list: " + repr(list) + "\n")
    # We replace a timeout "-" for 1 sec latency
    list = [lat.replace('-', '1000.00') for lat in list]
    list = [float(lat) for lat in list]  # we convert them to float
    mean = sum(list) / len(list)
    return mean


def max_list(list):
    if len(list) == 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot calculate max of list: " + repr(list) + "\n")
    # We replace a timeout "-" for 1 sec latency
    list = [lat.replace('-', '1000.00') for lat in list]
    list = [float(lat) for lat in list]
    max_lat = max(list)
    return max_lat


def min_list(list):
    if len(list) == 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "cannot calculate min of list: " + repr(list) + "\n")
    # We replace a timeout "-" for 1 sec latency
    list = [lat.replace('-', '1000.00') for lat in list]
    list = [float(lat) for lat in list]
    min_lat = min(list)
    return min_lat


def stddev_list(list, mean):
    if len(list) == 0:
        sys.exit(
            RED +
            "QUIT: " +
            NOCOLOR +
            "cannot calculate standard deviation of list: " +
            repr(list) +
            "\n")
    # We replace a timeout "-" for 1 sec latency
    list = [lat.replace('-', '1000.00') for lat in list]
    list = [float(lat) for lat in list]
    if PYTHON3:
        try:
            stddev_lat = statistics.stdev(list)
        except statistics.StatisticsError:
            # Assuming here the error is due 2 node run, not ideal
            stddev_lat = 0
    else:
        try:
            stddev_lat = sqrt(float(
                reduce(lambda x, y: x + y, map(
                    lambda x: (x - mean) ** 2, list))) / len(list))
        except TypeError:
            # Assuming here the error is due 2 node run, not ideal
            stddev_lat = 0
    stddev_lat = Decimal(stddev_lat)
    stddev_lat = round(stddev_lat, 2)
    return stddev_lat


def pct_diff_list(bw_str_list):
    # as the rest expects a str
    try:
        pc_diff_bw = abs(float(min_list(bw_str_list)) * 100 /
                         float(max_list(bw_str_list)))
    except BaseException:
        sys.exit(
            RED +
            "QUIT: " +
            NOCOLOR +
            "cannot calculate mean of bandwidth run")
    return pc_diff_bw


def file_exists(fileurl):
    # Lets check the files do actually exists
    if os.path.isfile(fileurl):
        pass
    else:
        sys.exit(RED + "QUIT: " + NOCOLOR + " cannot find file: " +
                 fileurl)


def load_json_files_into_dictionary(json_files_list):
    all_json_dict = {}
    try:
        for json_file in json_files_list:
            json_file_name = open(json_file, 'r')
            all_json_dict[json_file] = json.load(json_file_name)
        return all_json_dict
    except BaseException:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 " cannot load JSON file: " + json_file)


def load_throughput_tests(logdir, hosts_dictionary, many2many_clients):
    throughput_dict = {}
    nsd_lat_dict = {}
    nsd_std_dict = {}
    nsd_rxe_dict = {}
    nsd_rxe_m2m_d = {}
    nsd_txe_dict = {}
    nsd_txe_m2m_d = {}
    nsd_rtr_dict = {}
    nsd_rtr_m2m_d = {}
    file_host_dict = {}
    throughput_json_files_list = []
    for host in hosts_dictionary.keys():
        fileurl = logdir + "/nsd_" + host + ".json"
        file_exists(fileurl)
        # Lets do a load to check it is a proper file
        json_loads = json_file_loads(fileurl)
        if json_loads:
            throughput_json_files_list.append(fileurl)
            file_host_dict.update({fileurl: host})
        else:
            print(RED +
                  "ERROR: " +
                  NOCOLOR +
                  "cannot load JSON for host " +
                  host +
                  ". We are going to ignore this host on the results")
    # We append the mess run
    mess_file_url = logdir + "/nsd_mess.json"
    # Lets do a load to check it is a proper file
    json_loads = json_file_loads(mess_file_url)
    if json_loads:
            throughput_json_files_list.append(mess_file_url)
            file_host_dict.update({mess_file_url: "all at the same time"})
    else:
        print(RED +
              "ERROR: " +
              NOCOLOR +
              "cannot load JSON for all at the same time " +
              ". We are going to ignore this test on the results")
    # If the list is empty is that failed to load all JSON, no point to go
    if len(throughput_json_files_list) == 0:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 " cannot load any throughput JSON file")
    nsd_json = load_json_files_into_dictionary(throughput_json_files_list)
    for file in throughput_json_files_list:
        # here we add the metrics we will proces later
        host_key = file_host_dict[file]
        throughput_v = Decimal(nsd_json[file]['throughput(MB/sec)'])
        throughput_dict.update({host_key: throughput_v})
        n_lt_v = Decimal(nsd_json[file]['networkDelay'][0]['average'])
        nsd_lat_dict.update({host_key: n_lt_v})
        n_std = Decimal(nsd_json[file]['networkDelay'][0]['standardDeviation'])
        nsd_std_dict.update({host_key: n_std})
        if host_key == "all at the same time":
            for host in many2many_clients.keys():
                n_rxe = Decimal(nsd_json[file]['netData'][host]['rxerrors'])
                nsd_rxe_m2m_d.update({host: n_rxe})
                n_txe = Decimal(nsd_json[file]['netData'][host]['txerrors'])
                nsd_txe_m2m_d.update({host: n_txe})
                n_rtr = Decimal(nsd_json[file]['netData'][host]['retransmit'])
                nsd_rtr_m2m_d.update({host: n_rtr})
        else:
            n_rxe = Decimal(nsd_json[file]['netData'][host_key]['rxerrors'])
            nsd_rxe_dict.update({host_key: n_rxe})
            n_txe = Decimal(nsd_json[file]['netData'][host_key]['txerrors'])
            nsd_txe_dict.update({host_key: n_txe})
            n_rtr = Decimal(nsd_json[file]['netData'][host_key]['retransmit'])
            nsd_rtr_dict.update({host_key: n_rtr})

    # lets calculate % diff max min mean etc ...
    bw_str_list = []
    # filter "all" out of list of node bandwidths
    bw_str_list = [str(throughput_dict[k]) for k in throughput_dict
                   if k != 'all at the same time']
    pc_diff_bw = pct_diff_list(bw_str_list)
    max_bw = max_list(bw_str_list)
    min_bw = min_list(bw_str_list)
    mean_bw = mean_list(bw_str_list)
    stddev_bw = stddev_list(bw_str_list, mean_bw)
    pc_diff_bw = round(pc_diff_bw, 2)
    mean_bw = round(mean_bw, 2)
    return (throughput_dict, nsd_lat_dict, nsd_std_dict, pc_diff_bw, max_bw,
            min_bw, mean_bw, stddev_bw, nsd_rxe_dict, nsd_rxe_m2m_d,
            nsd_txe_dict, nsd_txe_m2m_d, nsd_rtr_dict, nsd_rtr_m2m_d)


def load_multiple_fping(logdir, hosts_dictionary):
    all_fping_dictionary = {}
    all_fping_dictionary_max = {}
    all_fping_dictionary_min = {}
    all_fping_dictionary_stddev = {}
    mean_all = []
    max_all = []
    min_all = []
    # Loads log file and returns dictionary
    for srchost in hosts_dictionary.keys():
        fileurl = os.path.join(logdir, "lat_" + srchost + "_all")
        file_exists(fileurl)
        logfping = open(fileurl, 'r')
        for rawfping in logfping:
            hostIP = rawfping.split(':')[0]
            hostIP = hostIP.rstrip(' ')
            if srchost == hostIP:  # we ignore ourselves
                continue
            latencies = rawfping.split(':')[1]
            latencies = latencies.lstrip(' ')  # Clean up first space
            latencies = latencies.rstrip('\n')  # Clean up new line character
            latencies_list = latencies.split(' ')
            # our mean calculation expect strings. Need to change this when
            # optimizing
            mean_all.append(str(mean_list(latencies_list)))
            max_all.append(max(latencies_list))
            min_all.append(min(latencies_list))
        # we use Decimal to round the results
        mean = Decimal(mean_list(mean_all))
        mean = round(mean, 2)  # we round to 2 decimals
        all_fping_dictionary[srchost] = mean
        all_fping_dictionary_max[srchost] = max_list(max_all)
        all_fping_dictionary_min[srchost] = min_list(min_all)
        all_fping_dictionary_stddev[srchost] = stddev_list(mean_all, mean)
        mean_all = []
        max_all = []
        min_all = []
    return (all_fping_dictionary, all_fping_dictionary_max,
            all_fping_dictionary_min, all_fping_dictionary_stddev)


def save_throughput_to_csv(logdir, throughput_dict):
    # We save per node and all to all
    fileurl = os.path.join(logdir, "throughput.csv")
    try:
        with open(fileurl, 'w') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["Host", "Throughput MB/sec"])
            for host in throughput_dict.keys():
                host_key = str(host)
                throughput_v = int(throughput_dict[host])
                csv_writer.writerow([host_key, throughput_v])
        print(
            GREEN +
            "INFO: " +
            NOCOLOR +
            "CSV file with throughput information can be found at " +
            fileurl
        )
    except BaseException:
        print(
            RED +
            "ERROR: " +
            NOCOLOR +
            "Cannot write throughput.csv file on " +
            logdir
            )
        sys.exit(1)


def nsd_KPI(min_nsd_throughput,
            throughput_dict,
            nsd_lat_dict,
            nsd_std_dict,
            pc_diff_bw,
            max_bw,
            min_bw,
            mean_bw,
            stddev_bw,
            nsd_rxe_dict,
            nsd_rxe_m2m_d,
            nsd_txe_dict,
            nsd_txe_m2m_d,
            nsd_rtr_dict,
            nsd_rtr_m2m_d):
    errors = 0
    print("Results for throughput test ")
    for host in throughput_dict.keys():
        if throughput_dict[host] < min_nsd_throughput:
            errors = errors + 1
            print(RED +
                  "ERROR: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the throughput test result is " +
                  str(throughput_dict[host]) +
                  " MB/sec. Which is less than the KPI of " +
                  str(min_nsd_throughput) +
                  " MB/sec")
        else:
            print(GREEN +
                  "OK: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the throughput test result is " +
                  str(throughput_dict[host]) +
                  " MB/sec. Which is higher than the KPI of " +
                  str(min_nsd_throughput) +
                  " MB/sec")

    if pc_diff_bw < 79:
        errors = errors + 1
        print(RED +
              "ERROR: " +
              NOCOLOR +
              "the difference of throughput between maximum and minimum " +
              "values is " + str(round((100 - pc_diff_bw), 2)) + "%, which is more " +
              "than 20% defined on the KPI")
    else:
        print(GREEN +
              "OK: " +
              NOCOLOR +
              "the difference of throughput between maximum and minimum " +
              "values is " + str(round((100 - pc_diff_bw), 2)) + "%, which is less " +
              "than 20% defined on the KPI")

    print("")
    print("The following metrics are not part of the KPI and " +
          "are shown for informational purposes only")
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The maximum throughput value is " + str(max_bw))
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The minimum throughput value is " + str(min_bw))
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The mean throughput value is " + str(mean_bw))
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The standard deviation throughput value is " + str(stddev_bw))
    for host in nsd_lat_dict.keys():
        print(GREEN +
              "INFO: " +
              NOCOLOR +
              "The average NSD latency for " +
              str(host) +
              " is " +
              str(nsd_lat_dict[host]) +
              " msec")
    for host in nsd_std_dict.keys():
        print(GREEN +
              "INFO: " +
              NOCOLOR +
              "The standard deviation of NSD latency for " +
              str(host) +
              " is " +
              str(nsd_std_dict[host]) +
              " msec")
    for host in nsd_rxe_dict.keys():
        print(GREEN +
              "INFO: " +
              NOCOLOR +
              "The packet Rx error count for throughput test on " +
              str(host) +
              " is equal to " +
              str(nsd_rxe_dict[host]) +
              " packet[s]")
    for host in nsd_txe_dict.keys():
        print(GREEN +
              "INFO: " +
              NOCOLOR +
              "The packet Tx error count for throughput test on " +
              str(host) +
              " is equal to " +
              str(nsd_txe_dict[host]) +
              " packet[s]")
    for host in nsd_rtr_dict.keys():
        print(GREEN +
              "INFO: " +
              NOCOLOR +
              "The packet retransmit count for throughput test on " +
              str(host) +
              " is equal to " +
              str(nsd_rtr_dict[host]) +
              " packet[s]")
    packets_rxe = 0
    for host in nsd_rxe_m2m_d.keys():
        packets_rxe = packets_rxe + nsd_rxe_m2m_d[host]
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The packet Rx error count for throughput test on many to many" +
          " is equal to " +
          str(packets_rxe) +
          " packet[s]")
    packets_txe = 0
    for host in nsd_txe_m2m_d.keys():
        packets_txe = packets_txe + nsd_txe_m2m_d[host]
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The packet Tx error count for throughput test on many to many" +
          " is equal to " +
          str(packets_txe) +
          " packet[s]")
    packets_rtr = 0
    for host in nsd_rtr_m2m_d.keys():
        packets_rtr = packets_rtr + nsd_rtr_m2m_d[host]
    print(GREEN +
          "INFO: " +
          NOCOLOR +
          "The packet retransmit count for throughput test many to many" +
          " is equal to " +
          str(packets_rtr) +
          " packet[s]")
    return errors


def fping_KPI(
        fping_dictionary,
        fping_dictionary_max,
        fping_dictionary_min,
        fping_dictionary_stddev,
        test_string,
        max_avg_latency,
        max_max_latency,
        max_stddev_latency,
        rdma_test,
        roce_test):
    errors = 0

    print("Results for ICMP latency test " + test_string + "")
    max_avg_latency_str = str(round(max_avg_latency, 2))
    max_max_latency_str = str(round(max_max_latency, 2))
    max_stddev_latency_str = str(round(max_stddev_latency, 2))
    for host in fping_dictionary.keys():
        if fping_dictionary[host] >= max_avg_latency:
            if rdma_test or roce_test:
                if fping_dictionary[host] >= 2*max_avg_latency:
                    errors = errors + 1  # yes yes +=
                    print(RED +
                        "ERROR: " +
                        NOCOLOR +
                        "on host " +
                        host +
                        " the " +
                        test_string +
                        " average ICMP latency is " +
                        str(fping_dictionary[host]) +
                        " msec. Which is higher than the 2*KPI of " +
                        max_avg_latency_str +
                        " msec")
                else:
                    # It is more than KPI but less than double on RDMA
                    print(YELLOW +
                        "WARNING: " +
                        NOCOLOR +
                        "on host " +
                        host +
                        " the " +
                        test_string +
                        " average ICMP latency is " +
                        str(fping_dictionary[host]) +
                        " msec. Which is higher than the KPI of " +
                        max_avg_latency_str +
                        " msec")
            else:
                errors = errors + 1  # yes yes +=
                print(RED +
                      "ERROR: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " average ICMP latency is " +
                      str(fping_dictionary[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_avg_latency_str +
                      " msec")
        else:
            print(GREEN +
                  "OK: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the " +
                  test_string +
                  " average ICMP latency is " +
                  str(fping_dictionary[host]) +
                  " msec. Which is lower than the KPI of " +
                  max_avg_latency_str +
                  " msec")

        if fping_dictionary_max[host] >= max_max_latency:
            if rdma_test or roce_test:
                print(YELLOW +
                      "WARNING: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " maximum ICMP latency is " +
                      str(fping_dictionary_max[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_max_latency_str +
                      " msec")
            else:
                errors = errors + 1
                print(RED +
                      "ERROR: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " maximum ICMP latency is " +
                      str(fping_dictionary_max[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_max_latency_str +
                      " msec")
        else:
            print(GREEN +
                  "OK: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the " +
                  test_string +
                  " maximum ICMP latency is " +
                  str(fping_dictionary_max[host]) +
                  " msec. Which is lower than the KPI of " +
                  max_max_latency_str +
                  " msec")

        if fping_dictionary_min[host] >= max_avg_latency:
            if rdma_test:
                print(YELLOW +
                      "WARNING: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " minimum ICMP latency is " +
                      str(fping_dictionary_min[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_avg_latency_str +
                      " msec")
            else:
                errors = errors + 1
                print(RED +
                      "ERROR: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " minimum ICMP latency is " +
                      str(fping_dictionary_min[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_avg_latency_str +
                      " msec")
        else:
            print(GREEN +
                  "OK: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the " +
                  test_string +
                  " minimum ICMP latency is " +
                  str(fping_dictionary_min[host]) +
                  " msec. Which is lower than the KPI of " +
                  max_avg_latency_str +
                  " msec")

        if fping_dictionary_stddev[host] >= max_stddev_latency:
            if rdma_test or roce_test:
                print(YELLOW +
                      "WARNING: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " standard deviation of ICMP latency is " +
                      str(fping_dictionary_stddev[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_stddev_latency_str +
                      " msec")
            else:
                errors = errors + 1
                print(RED +
                      "ERROR: " +
                      NOCOLOR +
                      "on host " +
                      host +
                      " the " +
                      test_string +
                      " standard deviation of ICMP latency is " +
                      str(fping_dictionary_stddev[host]) +
                      " msec. Which is higher than the KPI of " +
                      max_stddev_latency_str +
                      " msec")
        else:
            print(GREEN +
                  "OK: " +
                  NOCOLOR +
                  "on host " +
                  host +
                  " the " +
                  test_string +
                  " standard deviation of ICMP latency is " +
                  str(fping_dictionary_stddev[host]) +
                  " msec. Which is lower than the KPI of " +
                  max_stddev_latency_str +
                  " msec")
        print("")

    return errors  # Use this to give number of nodes is not exact in all cases


def test_ssh(hosts_dictionary):
    for host in hosts_dictionary.keys():
        try:
            ssh_return_code = subprocess.call(['ssh',
                                               '-o StrictHostKeyChecking=no',
                                               '-o BatchMode=yes',
                                               '-o ConnectTimeout=5',
                                               '-o LogLevel=error',
                                               host,
                                               'uname'],
                                              stdout=DEVNULL,
                                              stderr=DEVNULL)
            if ssh_return_code == 0:
                print(GREEN + "OK: " + NOCOLOR +
                      "SSH with node " + host + " works")
            else:
                sys.exit(
                    RED +
                    "QUIT: " +
                    NOCOLOR +
                    "cannot run ssh to " +
                    host +
                    ". Please fix this problem before running this tool again")
        except Exception:
            sys.exit(
                RED +
                "QUIT: " +
                NOCOLOR +
                "cannot run ssh to " +
                host +
                ". Please fix this problem before running this tool again")

        # Now lets see if the host keys are OK
        try:
            ssh_return_code = subprocess.call(['ssh',
                                               '-o StrictHostKeyChecking=yes',
                                               '-o BatchMode=yes',
                                               '-o ConnectTimeout=5',
                                               '-o LogLevel=error',
                                               host,
                                               'uname'],
                                              stdout=DEVNULL,
                                              stderr=DEVNULL)
            if ssh_return_code == 0:
                print(GREEN + "OK: " + NOCOLOR +
                      "SSH with node " + host + " works with strict host key checks")
            else:
                sys.exit(
                    RED +
                    "QUIT: " +
                    NOCOLOR +
                    "cannot run ssh to " +
                    host +
                    " with strict host key checks. Please fix this problem " +
                    "before running this tool again")
        except Exception:
            sys.exit(
                RED +
                "QUIT: " +
                NOCOLOR +
                "cannot run ssh to " +
                host +
                " with strict host key checks. Please fix this problem " +
                "before running this tool again")
    print("")


def print_end_summary(
        a_avg_fp_err,
        a_nsd_err,
        acceptance_flag):
    # End summary and say goodbye
    passed = True
    print("")
    print("The summary of this run:")
    print("")

    if a_avg_fp_err > 0:
        print(RED + "\tThe 1:n ICMP latency test failed " +
              str(a_avg_fp_err) + " time[s]" + NOCOLOR)
        passed = False
    else:
        print(
            GREEN +
            "\tThe 1:n ICMP average latency was successful in all nodes" +
            NOCOLOR)

    if a_nsd_err > 0:
        print(RED + "\tThe 1:n throughput test failed " +
              str(a_nsd_err) + " time[s]" + NOCOLOR)
        passed = False
    else:
        print(
            GREEN +
            "\tThe 1:n throughput test was successful in all nodes" +
            NOCOLOR)
    print("")

    if passed:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "All tests have passed" +
            NOCOLOR)
    else:
        print(
            RED +
            "ERROR: " +
            NOCOLOR +
            "All tests must be passed to certify the environment " +
            "before you proceed to the next step" +
            NOCOLOR)

    if acceptance_flag is True and passed is True:
        print(
            GREEN +
            "OK: " +
            NOCOLOR +
            "You can proceed to the next step" +
            NOCOLOR)
        valid_test = 0
    else:
        print(
            RED +
            "ERROR: " +
            NOCOLOR +
            "This test instance is invalid because KPI was lower than " +
            "requirement or parameters like count, runtime was " +
            "not enough. You cannot proceed to the next step" +
            NOCOLOR)
        valid_test = 5
    print("")
    return (a_avg_fp_err + a_nsd_err + valid_test)


def main():
    #Check files permissions
    fatal_error = check_permission_files()
    if fatal_error:
        sys.exit(RED + "QUIT: " + NOCOLOR + "there are files with "+
                 "unexpected permissions or non existing\n")

    # Parsing input
    fping_count, ttime_per_inst, test_thread, para_conn, buff_size, \
    socket_size, cli_hosts, hosts_dictionary, rdma_test, rdma_ports_list, \
    roce_test, roce_ports_list, no_rpm_check, save_hosts = \
        parse_arguments()
    rdma_ports_csv_mlx = []
    roce_ports_csv_mlx = []

    # JSON loads
    os_dictionary = load_json("supported_OS.json")
    packages_dictionary = load_json("packages.json")

    # Check OS
    linux_distribution = check_distribution()
    if linux_distribution in ["redhat", "centos"]:
        redhat8 = check_os_redhat(os_dictionary)
    else:
        sys.exit(RED + "QUIT: " + NOCOLOR +
                 "this is not a supported Linux distribution for this tool\n")
    packages_roce_dictionary = None
    if redhat8:
        packages_rdma_dictionary = load_json("packages_rdma_rh8.json")
        packages_roce_dictionary = load_json("packages_roce_rh8.json")
    else:
        packages_rdma_dictionary = load_json("packages_rdma.json")

    if not cli_hosts:
        hosts_dictionary = load_json("hosts.json")

    # Check hosts are IP addresses
    check_hosts_are_ips(hosts_dictionary)

    # Check hosts are 2 to 64
    check_hosts_number(hosts_dictionary)

    # Initial header
    json_version = get_json_versions(
                                    os_dictionary,
                                    packages_dictionary,
                                    packages_roce_dictionary,
                                    packages_rdma_dictionary)
    estimated_runtime_str = str(estimate_runtime(hosts_dictionary,
                                fping_count, ttime_per_inst))
    show_header(VERSION, json_version, estimated_runtime_str, fping_count,
                ttime_per_inst, test_thread, para_conn, buff_size,
                socket_size)

    # JSON hosts write
    if save_hosts:
        write_json_file_from_dictionary(hosts_dictionary, "hosts.json")


    # Check local node is included on the test
    check_localnode_is_in(hosts_dictionary)

    # Check SSH
    test_ssh(hosts_dictionary)

    # Check packages are installed
    print("Pre-flight generic checks:")
    if no_rpm_check:
        print(YELLOW + "WARNING: " + NOCOLOR +
              "you have disabled RPM checks, things might break")
    else:
        host_packages_check(hosts_dictionary, packages_dictionary)

    #Check firewalld is down
    firewalld_check(hosts_dictionary)
    # Check TCP port 6668 is not in use. Limited from view of this host
    check_tcp_port_free(hosts_dictionary, 6668)
    print("")

    # If RDMA lets get the ports on a dictionary
    if rdma_test:
        # Lets check that we have the RDMA needed SW
        print("Pre-flight RDMA checks:")
        if no_rpm_check:
            print(YELLOW + "WARNING: " + NOCOLOR +
                  "you have disabled RPM checks, things might break")
        else:
            host_packages_check(hosts_dictionary, packages_rdma_dictionary)
        rdma_port_error, rdma_ports_csv_mlx = check_rdma_ports(
                                                            hosts_dictionary,
                                                            rdma_ports_list)
        if not rdma_port_error:
            print(GREEN + "OK: " + NOCOLOR +
                  "all RDMA ports are up on all nodes")
        else:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "not all RDMA ports are up on all nodes\n")
        print("")

    # If RoCE lets get the ports on a dictionary
    if roce_test:
        # Lets check that we have the RoCE needed SW
        print("Pre-flight RoCE checks:")
        if no_rpm_check:
            print(YELLOW + "WARNING: " + NOCOLOR +
                  "you have disabled RPM checks, things might break")
        else:
            host_packages_check(hosts_dictionary, packages_roce_dictionary)
        roce_port_error, roce_ports_csv_mlx = check_roce_ports(
                                                            hosts_dictionary,
                                                            roce_ports_list)
        if not roce_port_error:
            print(GREEN + "OK: " + NOCOLOR +
                  "all RoCE ports are up on all nodes")
        else:
            sys.exit(RED + "QUIT: " + NOCOLOR +
                     "not all RoCE ports are up on all nodes\n")
        print("")

    # Run
    log_dir_timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    logdir = create_local_log_dir(log_dir_timestamp)
    create_log_dir(hosts_dictionary, log_dir_timestamp)
    latency_test(hosts_dictionary, logdir, fping_count)
    many2many_clients = throughput_test(hosts_dictionary,
                                        logdir,
                                        ttime_per_inst,
                                        test_thread,
                                        para_conn,
                                        buff_size,
                                        socket_size,
                                        rdma_test,
                                        rdma_ports_csv_mlx,
                                        roce_test,
                                        roce_ports_csv_mlx)

    # Load results
    all_fping_dictionary, all_fping_dictionary_max, all_fping_dictionary_min, \
        all_fping_dictionary_stddev = load_multiple_fping(logdir,
                                                          hosts_dictionary)
    throughput_dict, nsd_lat_dict, nsd_std_dict, pc_diff_bw, max_bw, min_bw, \
        mean_bw, stddev_bw, nsd_rxe_dict, nsd_rxe_m2m_d, nsd_txe_dict, \
        nsd_txe_m2m_d, nsd_rtr_dict, nsd_rtr_m2m_d = load_throughput_tests(
                                                        logdir,
                                                        hosts_dictionary,
                                                        many2many_clients)

    # Compare againsts KPIs
    print("")
    all_avg_fping_errors = fping_KPI(
        all_fping_dictionary,
        all_fping_dictionary_max,
        all_fping_dictionary_min,
        all_fping_dictionary_stddev,
        "1:n",
        KPI_AVG_LATENCY,
        KPI_MAX_LATENCY,
        KPI_STDDEV_LTNC,
        rdma_test,
        roce_test)
    all_nsd_errors = nsd_KPI(KPI_NSD_THROUGH, throughput_dict, nsd_lat_dict,
                             nsd_std_dict, pc_diff_bw, max_bw, min_bw,
                             mean_bw, stddev_bw, nsd_rxe_dict, nsd_rxe_m2m_d,
                             nsd_txe_dict, nsd_txe_m2m_d, nsd_rtr_dict,
                             nsd_rtr_m2m_d)

    acceptance_flag = check_parameters(
                          fping_count,
                          ttime_per_inst,
                          test_thread,
                          para_conn,
                          buff_size,
                          socket_size)

    save_throughput_to_csv(
        logdir,
        throughput_dict
    )
    DEVNULL.close()
    return_code = print_end_summary(
        all_avg_fping_errors,
        all_nsd_errors,
        acceptance_flag)
    print("")
    return return_code


if __name__ == '__main__':
    main()

