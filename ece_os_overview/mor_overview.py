"""Module overall checks of homogeneity of given json files
"""
import json
import argparse
import os
import sys
from typing import Tuple, Dict

# This Module version
MODULE_VER = "2.00"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESETCOL = '\033[0m'

# Message labels
INFO = f"[ {GREEN}INFO{RESETCOL}  ]"
WARN = f"[ {YELLOW}WARN{RESETCOL}  ]"
ERROR = f"[ {RED}FATAL{RESETCOL} ]"

# A minimum of 3 and maximum of 32 nodes per recovery group is supported.
MIN_NODE_NUM = 3
MAX_NODE_NUM_PER_RG = 32
# A maximum of 128 IBM Storage Scale Erasure Code Edition storage nodes per
# cluster is supported.
MAX_NODE_NUM = 128

# Restrictions
# Memory size margin: 6 GiB
MEM_SIZE_MARGIN = 6
# A maximum of 512 drives per recovery group is supported
MAX_DEV_NUM_PER_RG = 512
# At least one declustered array must contain 12 or more drives.
MIN_DEV_NUM_ALO_DA = 12
# Every DA must have 4 or more drives.
MIN_DEV_NUM_PER_DA = 4
# A maximum of 64 drives per storage node is supported.
MAX_DEV_NUM_PER_NODE = 64



def parse_arguments() -> Tuple[str, str, bool]:
    """Parse input arguments.
    Args:
    Returns:
        (json_files, json_dir, skip_check)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--json-files',
        required=True,
        action='store',
        dest='json_files',
        help='Comma-separated Json files',
        metavar='JSON_FILES',
        type=str)

    parser.add_argument(
        '--no-check',
        action='store_true',
        dest='skip_check',
        help='Skip all homogeneity checks',
        default=False)

    parser.add_argument(
        '--path',
        action='store',
        dest='path',
        help='where JSON files are located. Default is current directory',
        metavar='PATH',
        type=str,
        default='./')

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='IBM Storage Scale Erasure Code Edition (ECE) OS ' +
        f"readiness overview version: {MODULE_VER}")

    args = parser.parse_args()
    jsonfile_str = args.json_files
    json_files = jsonfile_str.split(',')
    node_num = len(json_files)
    if node_num <= 0:
        sys.exit(f"{ERROR} Invalid json file number: {node_num}\n")
    elif node_num < MIN_NODE_NUM:
        sys.exit(f"{ERROR} Too few separate json files. The ECE cluster must " +
                 f"have at least {MIN_NODE_NUM} storage servers")
    elif node_num <= MAX_NODE_NUM_PER_RG:
        pass
    elif node_num <= MAX_NODE_NUM:
        print(f"{INFO} NOTE: One recovery group must have at most " +
              f"{MAX_NODE_NUM_PER_RG} storage servers")
    elif node_num > MAX_NODE_NUM:
        sys.exit(f"{ERROR} Too many separate json files. The ECE cluster " +
                 f"supports at most {MAX_NODE_NUM} storage servers\n")

    json_dir = args.path
    try:
        json_dir = os.path.normpath(json_dir)
    except BaseException as e:
        sys.exit(f"{ERROR} Tried to normalize path: {json_dir} but hit " +
                 f"exception: {e}\n")

    return json_files, json_dir, args.skip_check


def check_file_presence(json_dir: str, json_files: str) -> int:
    """Do all the input files exist?
    Args:
        json_dir: where the files located.
        json_files: file list.
    Returns:
        count of errors.
    """
    errcnt = 0
    if not json_dir or isinstance(json_dir, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_dir: {json_dir}")
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if errcnt != 0:
        return errcnt

    for jf in json_files:
        filepath = os.path.join(json_dir, jf)
        if os.path.isfile(filepath) is False:
            errcnt += 1
            print(f"{ERROR} {filepath} does not exist")
    return errcnt


def collect_check_results(json_dir: str, json_files: str) -> Dict[str, Dict]:
    """Collect separate check results to a Python dictionary.
    Args:
        json_dir: where the json files located.
        json_files: json file list.
    Returns:
        KV pairs collected from separate files.
    """
    errcnt = 0
    if not json_dir or isinstance(json_dir, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_dir: {json_dir}")
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if errcnt != 0:
        return {}

    coll_kv = {}
    for jf in json_files:
        filepath = os.path.join(json_dir, jf)
        content_kv = {}
        try:
            with open(filepath, mode="r", encoding="utf-8") as fh:
                content_kv = json.load(fh)
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while loading {filepath}")
            continue
        if not content_kv:
            errcnt += 1
            print(f"{ERROR} Cannot translate content of {jf} to KV pair")
            continue
        coll_kv[jf] = content_kv

    if errcnt != 0:
        coll_kv = {}
    return coll_kv


def review_top_conclusions(json_files: str, all_in_one_kv: Dict) -> int:
    """Review the top conclusion of each json file.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        error count of the checks.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    nodeready_states = []
    nodeready_stat_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        nodeready = False
        hostnm = ''
        try:
            hostnm = all_in_one_kv[jf]['local_hostname']
            nodeready = all_in_one_kv[jf]['ECE_node_ready']
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting hostname or " +
                  f"node-ready info of {node}")
            continue
        if not hostnm:
            errcnt += 1
            print(f"{ERROR} Cannot extract hostname of {node}")
            continue
        if isinstance(nodeready, bool) is False:
            errcnt += 1
            print(f"{ERROR} Cannot extract node ready info of {node}")
            continue
        nodeready_states.append(nodeready)
        nodeready_stat_kv[node] = nodeready
    if errcnt != 0:
        return errcnt

    dedup_nr_states = list(set(nodeready_states))
    dedup_nr_st_len = len(dedup_nr_states)
    if dedup_nr_st_len == 1:
        nodeready_st = dedup_nr_states[0]
        if nodeready_st is True:
            print(f"{INFO} All nodes marked the node ready state as True")
            return 0
        print(f"{ERROR} All nodes marked the node ready state as False")
        return 1
    print(f"{ERROR} Not all nodes have the same node ready state")
    for k, v in nodeready_stat_kv.items():
        if v is True:
            print(f"{INFO} node ready state of {k} is {v}")
        else:
            print(f"{ERROR} node ready state of {k} is {v}")
    return 1


def check_processor_name(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if system processor names are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if processor name was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    proc_names = []
    proc_name_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        proc_name = ''
        try:
            proc_name = all_in_one_kv[jf]['processor_name']
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting processor " +
                  f"name of {node}")
            continue
        if not proc_name:
            errcnt += 1
            print(f"{ERROR} Cannot extract processor name of {node}")
            continue
        proc_names.append(proc_name)
        proc_name_kv[node] = proc_name
    if errcnt != 0:
        return errcnt

    dedup_proc_names = list(set(proc_names))
    dedup_proc_name_len = len(dedup_proc_names)
    if dedup_proc_name_len == 1:
        proc_name_str = dedup_proc_names[0]
        print(f"{INFO} All nodes have the same processor architecture: " +
              f"{proc_name_str}")
        return 0
    print(f"{ERROR} Not all nodes have the same processor architecture")
    for k, v in proc_name_kv.items():
        print(f"{WARN} processor architecture of {k} is {v}")
    return 1


def check_cpu_socket(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if CPU sockets are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if CPU socket number was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    sock_nums = []
    sock_num_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        sock_num = 0
        try:
            sock_num = int(all_in_one_kv[jf]['CPU_socket_num'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting CPU socket " +
                  f"number of {node}")
            continue
        if sock_num <= 0:
            errcnt += 1
            print(f"{ERROR} {node} has invalid CPU socket number: {sock_num}")
            continue
        sock_nums.append(sock_num)
        sock_num_kv[node] = sock_num
    if errcnt != 0:
        return errcnt

    dedup_sock_nums = list(set(sock_nums))
    dedup_sock_num_len = len(dedup_sock_nums)
    if dedup_sock_num_len == 1:
        socknum = dedup_sock_nums[0]
        print(f"{INFO} All nodes have the same CPU socket number: {socknum}")
        return 0
    print(f"{ERROR} Not all nodes have the same CPU socket number")
    for k, v in sock_num_kv.items():
        print(f"{WARN} {k} has {v} CPU socket[s]")
    return 1


def check_cpu_core(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if CPU cores are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if CPU cores per socket was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    core_distributions = []
    core_dist_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        core_dists = []
        try:
            core_dists = all_in_one_kv[jf]['CPU_cores_per_socket']
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting CPU core " +
                  f"distribution on {node}")
            continue
        if not core_dists:
            errcnt += 1
            print(f"{ERROR} Cannot extract CPU core distribution on {node}")
            continue
        core_distributions.append(tuple(core_dists))
        core_dist_kv[node] = core_dists
    if errcnt != 0:
        return errcnt

    dedup_core_distrs = list(set(core_distributions))
    dedup_core_dist_len = len(dedup_core_distrs)
    if dedup_core_dist_len == 1:
        coredist = list(dedup_core_distrs[0])
        print(f"{INFO} All nodes have the same CPU core distribution: " +
              f"{coredist}")
        return 0
    print(f"{ERROR} Not all nodes have the same CPU cores per socket")
    for k, v in core_dist_kv.items():
        print(f"{WARN} {k} has CPU core distribution: {list(v)}")
    return 1


def check_populated_dimm_slot_number(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if vacant number of DIMM socket is the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if populated DIMM slot number was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    pplt_dimm_slot_nums = []
    pplt_dimm_slot_num_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        pplt_dimm_slot_num = -1
        try:
            pplt_dimm_slot_num = \
                int(all_in_one_kv[jf]['populated_dimm_slot_num'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting number of " +
                  f"populated DIMM slot on {node}")
            continue
        if pplt_dimm_slot_num < 0:
            errcnt += 1
            print(f"{ERROR} {node} has invalid populated DIMM slot number: " +
                  f"{pplt_dimm_slot_num}")
            continue
        pplt_dimm_slot_nums.append(pplt_dimm_slot_num)
        pplt_dimm_slot_num_kv[node] = pplt_dimm_slot_num
    if errcnt != 0:
        return errcnt

    dedup_pplt_dimm_slot_nums = list(set(pplt_dimm_slot_nums))
    dedup_pplt_dimm_slot_num_len = len(dedup_pplt_dimm_slot_nums)
    if dedup_pplt_dimm_slot_num_len == 1:
        uniq_pplt_dimm_num = dedup_pplt_dimm_slot_nums[0]
        print(f"{INFO} All nodes have the same vacant DIMM slot number: " +
              f"{uniq_pplt_dimm_num}")
        return 0
    print(f"{ERROR} Not all nodes have the same vacant DIMM slot number")
    for k, v in pplt_dimm_slot_num_kv.items():
        print(f"{WARN} {k} has {v} vacant DIMM slot[s]")
    return 1


def check_memory_size(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if memory sizes are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if memory size was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    mem_sizes = []
    mem_size_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        mem_sz = 0.0
        try:
            mem_sz = float(all_in_one_kv[jf]['memory_size'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting memory size " +
                  f"of {node}")
            continue
        if int(mem_sz) <= 0:
            errcnt += 1
            print(f"{ERROR} {node} has invalid memory size: {mem_sz}")
            continue
        mem_sizes.append(mem_sz)
        mem_size_kv[node] = mem_sz
    if errcnt != 0:
        return errcnt

    dedup_mem_sizes = list(set(mem_sizes))
    dedup_mem_size_len = len(dedup_mem_sizes)
    if dedup_mem_size_len == 1:
        memsize = dedup_mem_sizes[0]
        print(f"{INFO} All nodes have the same memory size: {memsize} GiB")
        return 0
    min_mem_size = min(dedup_mem_sizes)
    max_mem_size = max(dedup_mem_sizes)
    diff_size = int(max_mem_size - min_mem_size)
    if diff_size <= MEM_SIZE_MARGIN:
        print(f"{INFO} Not all nodes have the same memory size. But the " +
              "different margin is within the limits of " +
              f"{MEM_SIZE_MARGIN} GiBytes")
        for k, v in mem_size_kv.items():
            print(f"{INFO} Memory size of {k} is {v} GiB")
        return 0
    print(f"{ERROR} Not all nodes have the same memory size")
    for k, v in mem_size_kv.items():
        print(f"{WARN} Memory size of {k} is {v} GiB")
    return 1


def check_net_controller(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if network controllers are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if network controller was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or \
       isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    node_num = len(json_files)
    no_explicit_net_ctrlr_cnt = 0
    net_controllers = []
    net_ctrlr_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        netctrlr_str = ''
        try:
            net_ctrlrs = all_in_one_kv[jf]['network_controllers']
            netctrlr_str = ", ".join(net_ctrlrs)
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting network " +
                  f"controller on {node}")
            continue
        if not netctrlr_str:
            no_explicit_net_ctrlr_cnt += 1
            netctrlr_str = '[[No explicitly certificated network controller]]'
            print(f"{WARN} {node} does not have any explicitly certificated " +
                  "network controller")
        net_controllers.append(netctrlr_str)
        net_ctrlr_kv[node] = netctrlr_str
    if errcnt != 0:
        return errcnt
    if no_explicit_net_ctrlr_cnt == node_num:
        return 0

    dedup_net_ctrlrs = list(set(net_controllers))
    dedup_net_ctrlr_len = len(dedup_net_ctrlrs)
    if dedup_net_ctrlr_len == 1:
        netctrlr = dedup_net_ctrlrs[0]
        print(f"{INFO} All nodes have the same network controller: {netctrlr}")
    else:
        print(f"{WARN} Not all nodes have the same network controller[s]")
        for k, v in net_ctrlr_kv.items():
            print(f"{WARN} {k} has {v}")
    return 0


def check_netif_speed(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if network interface link speeds are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if network interface link speed was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or \
       isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    net_speeds = []
    net_speed_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        net_speed = 0
        try:
            net_speed = int(all_in_one_kv[jf]['network_interface_speed'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting network " +
                  f"interface speed of {node}")
            continue
        if net_speed <= 0:
            errcnt += 1
            print(f"{ERROR} {node} has invalid network interface speed: " +
                  f"{net_speed}")
            continue
        net_speeds.append(net_speed)
        net_speed_kv[node] = net_speed
    if errcnt != 0:
        return errcnt

    dedup_net_speeds = list(set(net_speeds))
    dedup_net_speed_len = len(dedup_net_speeds)
    if dedup_net_speed_len == 1:
        netspeed = dedup_net_speeds[0]
        print(f"{INFO} All nodes have the same to-be-used network interface " +
              f"link speed: {netspeed} Mb/s")
    else:
        errcnt += 1
        print(f"{ERROR} Not all nodes have the same to-be-used network " +
              "interface link speed")
        for k, v in net_speed_kv.items():
            print(f"{WARN} Network interface link speed to be used on {k} is " +
                  f"{v} Mb/s")
    return errcnt


def check_scsi_controller(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check if SCSI controllers are the same in input files.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if SCSI controller was the same on all nodes.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    scsi_controllers = []
    scsi_ctrlr_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        scsictrlrs_str = ''
        try:
            scsi_ctrlrs = all_in_one_kv[jf]['SCSI_controllers']
            scsictrlrs_str = ", ".join(scsi_ctrlrs)
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting SCSI " +
                  f"controller on {node}")
            continue
        if not scsictrlrs_str:
            print(f"{WARN} Cannot extract SCSI controller on {node}")
            scsictrlrs_str = 'None'
        scsi_controllers.append(scsictrlrs_str)
        scsi_ctrlr_kv[node] = scsictrlrs_str
    if errcnt != 0:
        return errcnt

    dedup_scsi_ctrlrs = list(set(scsi_controllers))
    dedup_scsi_ctrlr_len = len(dedup_scsi_ctrlrs)
    if dedup_scsi_ctrlr_len == 1:
        scsictrlr = dedup_scsi_ctrlrs[0]
        if scsictrlr == 'None':
            print(f"{WARN} No SCSI controller info found in the input files for any of the nodes")
            print(f"{WARN} If the nodes are known to not have SCSI controllers ignore this warning")
        print(f"{INFO} All nodes have the same SCSI controller: {scsictrlr}")
    else:
        print(f"{WARN} Not all nodes have the same SCSI controller[s]")
        for k, v in scsi_ctrlr_kv.items():
            print(f"{WARN} {k} has {v}")
    return 0


def count_number_of_disk_by_devtype(
        json_files: str,
        all_in_one_kv: Dict,
        dev_type) -> Tuple[int, int]:
    """Count total disk number classed by disk type.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
        dev_type: in ['NVMe', 'SSD', 'HDD'].
    Returns:
        (errcnt, total_dev_num)
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if not dev_type or isinstance(dev_type, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter dev_type: {dev_type}")
    devtypes = ['NVMe', 'SSD', 'HDD']
    if dev_type not in devtypes:
        errcnt += 1
        print(f"{ERROR} dev_type should be chosen from {devtypes}")
    if errcnt != 0:
        return errcnt, 0

    node_num = len(json_files)

    dev_err_key = f"{dev_type}_error"
    dev_num_key = ''
    if dev_type == 'NVMe':
        dev_num_key = f"{dev_type}_drive_number"
    else:
        dev_num_key = f"{dev_type}_device_number"

    deverr_true_nodes = []
    deverr_false_nodes = []
    certdev_nums = []
    certdev_ttl_num = 0
    certdev_num_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} cannot extract node IP")
            continue
        dev_err = True
        dev_num = 0
        try:
            dev_err = all_in_one_kv[jf][dev_err_key]
            dev_num = int(all_in_one_kv[jf][dev_num_key])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting {dev_type} " +
                  f"error state or disk number on {node}")
            continue
        if dev_err is True:
            deverr_true_nodes.append(node)
        elif dev_err is False:
            deverr_false_nodes.append(node)
        else:
            errcnt += 1
            print(f"{ERROR} {node} has invalid {dev_type} error state: " +
                  f"'{dev_err}'")
            continue
        if isinstance(dev_num, int) is False:
            errcnt += 1
            print(f"{ERROR} Cannot extract {dev_type} disk number on {node}")
            continue
        certdev_nums.append(dev_num)
        certdev_ttl_num += dev_num
        certdev_num_kv[node] = dev_num
    if errcnt != 0:
        return errcnt, 0

    deverr_true_num = len(deverr_true_nodes)
    deverr_false_num = len(deverr_false_nodes)
    if deverr_true_num == node_num and deverr_false_num == 0:
        print(f"{INFO} All nodes hit {dev_type} error. They may not have " +
              f"available {dev_type} device")
        if certdev_ttl_num > 0:
            errcnt += 1
            print(f"{ERROR} All nodes have a total of {certdev_ttl_num} " +
                  f"{dev_type} device. But they got error[s] of such device")
    elif deverr_false_num == node_num and deverr_true_num == 0:
        dedup_nums = list(set(certdev_nums))
        dedup_num_len = len(dedup_nums)
        if dedup_num_len == 1:
            certdev_per_node = int(dedup_nums[0])
            if certdev_per_node == 0:
                print(f"{INFO} All nodes have no {dev_type} device")
            else:
                print(f"{INFO} All nodes have the same {dev_type} device " +
                      f"number: {certdev_per_node}")
        else:
            print(f"{WARN} Not all nodes have the same {dev_type} device " +
                  "number")
            for k, v in certdev_num_kv.items():
                if v <= 0:
                    errcnt += 1
                    print(f"{ERROR} {k} has {v} {dev_type} device[s]")
                else:
                    print(f"{WARN} {k} has {v} {dev_type} device[s]")
        if 0 < certdev_ttl_num < MIN_DEV_NUM_PER_DA:
            errcnt += 1
            print(f"{WARN} This cluster has a total {dev_type} device " +
                  f"number: {certdev_ttl_num}. But the number is too small " +
                  "to be built as a declustered array (DA)")
        elif certdev_ttl_num >= MIN_DEV_NUM_PER_DA:
            print(f"{INFO} This cluster has a total {dev_type} device " +
                  f"number: {certdev_ttl_num}")
    elif 0 < deverr_true_num < node_num and \
         0 < deverr_false_num < node_num and \
         (deverr_true_num + deverr_false_num == node_num):
        print(f"{WARN} Not all nodes have the same {dev_type} error state")
        if deverr_true_nodes:
            for n in deverr_true_nodes:
                print(f"{WARN} {n} hit {dev_type} device error")
        if deverr_false_nodes:
            for n in deverr_false_nodes:
                print(f"{INFO} {n} does not hit {dev_type} device error")
        if certdev_ttl_num > 0:
            errcnt += 1
            print(f"{ERROR} This cluster has a total of {certdev_ttl_num} " +
                  f"{dev_type} device. However, the {dev_type} error " +
                  "states of the nodes are different")
        else:
            print(f"{INFO} Even if the nodes have different {dev_type} " +
                  "error states, the cluster does not have any {dev_type} " +
                  "device")
    else:
        print(f"{ERROR} This tool hit unexpected error. Failed to " +
              "calculate error state of {dev_type}. Node number: " +
              f"{node_num}, deverr_true_num: {deverr_true_num}, " +
              f"deverr_false_num: {deverr_false_num}")
    return errcnt, certdev_ttl_num


def check_nvme_id(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check eui, nguid of NVMe drives.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if all euis, nguids of NVMe drives are unique.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    euis = []
    nguids = []
    zero_eui = '0000000000000000'
    zero_nguid = '00000000000000000000000000000000'
    duplicate_cnt = 0
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} Cannot extract node IP")
            continue
        nvid_kv = {}
        try:
            nvid_kv = all_in_one_kv[jf]['NVMe_ID_KV']
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting NVMe drive ID " +
                  f"KV pair of {node}")
            continue
        if not nvid_kv:
            errcnt += 1
            print(f"{ERROR} Cannot extract NVMe drive ID KV pair of {node}")
            continue
        for key, val in nvid_kv.items():
            eui = ''
            nguid = ''
            try:
                eui = str(val[0])
                nguid = str(val[1])
            except KeyError as e:
                errcnt += 1
                print(f"{ERROR} Hit KeyError: {e} while extracting NVMe " +
                      f"eui or nguid of {node}:{key}")
                continue
            if (not eui) or (not nguid):
                errcnt += 1
                print(f"{ERROR} Cannot extract NVMe drive eui or nguid of " +
                      f"{node}:{key}")
                continue
            if eui != zero_eui and eui in euis:
                duplicate_cnt += 1
            else:
                euis.append(eui)

            if nguid != zero_nguid and nguid in nguids:
                duplicate_cnt += 1
            else:
                nguids.append(nguid)
    if errcnt != 0:
        return errcnt

    if duplicate_cnt == 0:
        print(f"{INFO} All NVMe drives in this cluster have unique euis and " +
              "nguids")
        return 0
    print(f"{ERROR} NVMe drives in this cluster have {duplicate_cnt} " +
          "duplicate eui or nguid")
    return 1


def check_storage_device_wwn(
        json_files: str,
        all_in_one_kv: Dict,
        dev_type: str) -> int:
    """Check wwn of SCSI storage devices.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
        dev_type: in ['SSD', 'HDD'].
    Returns:
        0 if all wwn of SCSI storage devices are unique.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if not dev_type or isinstance(dev_type, str) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter dev_type: {dev_type}")
    devtypes = ['SSD', 'HDD']
    if dev_type not in devtypes:
        errcnt += 1
        print(f"{ERROR} dev_type should be chosen from {devtypes}")
    if errcnt != 0:
        return errcnt

    dev_kv_key = f"{dev_type}_KV"

    wwns = []
    duplicate_cnt = 0
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} Cannot extract node IP")
            continue
        dev_kv = {}
        try:
             dev_kv = all_in_one_kv[jf][dev_kv_key]
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting {dev_type} " +
                  f"device KV pair of {node}")
            continue
        if not dev_kv:
            errcnt += 1
            print(f"{ERROR} Cannot extract {dev_type} device KV pair of {node}")
            continue

        for key, val in dev_kv.items():
            wwn = ''
            try:
                wwn = str(val[4])
            except KeyError as e:
                errcnt += 1
                print(f"{ERROR} Hit KeyError: {e} while extracting wwn of " +
                      f"{node}-{key}")
                continue
            if not wwn:
                errcnt += 1
                print(f"{ERROR} Cannot extract wwn of {node}-{key}")
                continue
            if wwn in wwns:
                duplicate_cnt += 1
            else:
                wwns.append(wwn)
    if errcnt != 0:
        return errcnt

    if duplicate_cnt == 0:
        print(f"{INFO} All {dev_type} devices in this cluster have unique wwns")
        return 0

    print(f"{ERROR} {dev_type} devices in this cluster have " +
          f"{duplicate_cnt} uplicate wwn")
    return 1


def check_all_valid_storage_device_number(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check all valid storage device number.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if all of SCSI storage devices are unique.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    dev_nums = []
    total_dev_num = 0
    dev_num_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} Cannot extract node IP")
            continue
        dev_num = 0
        try:
            dev_num = int(all_in_one_kv[jf]['valid_storage_device_number'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting all valid " +
                  f"storage device number on {node}")
            continue
        if isinstance(dev_num, int) is False:
            errcnt += 1
            print(f"{ERROR} Cannot extract all valid storage device number " +
                  f"on {node}")
            continue
        dev_nums.append(dev_num)
        total_dev_num += dev_num
        dev_num_kv[node] = dev_num
    if errcnt != 0:
        return errcnt

    dedup_dev_nums = list(set(dev_nums))
    dedup_dev_num_len = len(dedup_dev_nums)
    if dedup_dev_num_len == 1:
        alltype_devnum = dedup_dev_nums[0]
        print(f"{INFO} All nodes have the same total storage device number: " +
              f"{alltype_devnum}")
        dev_num_per_node = int(dedup_dev_nums[0])
        if dev_num_per_node > MAX_DEV_NUM_PER_NODE:
            print(f"{WARN} Each node has too many storage device number: " +
                  f"{dev_num_per_node}. The restriction is " +
                  f"{MAX_DEV_NUM_PER_NODE} per node")
    else:
        print(f"{WARN} Not all nodes have the same valid storage device number")
        for k, v in dev_num_kv.items():
            print(f"{WARN} {k} has a total of {v} valid storage device[s]")

    if total_dev_num == 0:
        errcnt += 1
        print(f"{ERROR} There is no valid storage device can be used by the " +
              "ECE cluster")
    elif total_dev_num < MIN_DEV_NUM_ALO_DA:
        errcnt += 1
        print(f"{ERROR} This cluster has a total valid storage device " +
              f"number: {total_dev_num}. But the restriction is at least one " +
              f"declustered array (DA) must have {MIN_DEV_NUM_ALO_DA} or " +
              "more storage devices")
    else:
        print(f"{INFO} This cluster has a total storage device number: " +
              f"{total_dev_num}")
        if total_dev_num > MAX_DEV_NUM_PER_RG:
            print(f"{WARN} NOTE: One recovery group can accommodate up to " +
                  f"{MAX_DEV_NUM_PER_RG} storage devices")
    return errcnt


def check_system_serial_number(
        json_files: str,
        all_in_one_kv: Dict) -> int:
    """Check all valid storage device number.
    Args:
        json_files: json file list.
        all_in_one_kv: all check result KV pairs.
    Returns:
        0 if all of SCSI storage devices are unique.
        Else, the error count.
    """
    errcnt = 0
    if not json_files or isinstance(json_files, list) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter json_files: {json_files}")
    if not all_in_one_kv or isinstance(all_in_one_kv, dict) is False:
        errcnt += 1
        print(f"{ERROR} Invalid parameter all_in_one_kv: {all_in_one_kv}")
    if errcnt != 0:
        return errcnt

    ser_nums = []
    duplicate_cnt = 0
    ser_num_kv = {}
    for jf in json_files:
        node = ''
        try:
            fn = os.path.basename(jf)
            node = os.path.splitext(fn)[0]
        except BaseException as e:
            errcnt += 1
            print(f"{ERROR} Hit exception: {e} while extracting node IP")
            continue
        if not node:
            errcnt += 1
            print(f"{ERROR} Cannot extract node IP")
            continue
        ser_num = ''
        try:
            ser_num = str(all_in_one_kv[jf]['system_serial_number'])
        except KeyError as e:
            errcnt += 1
            print(f"{ERROR} Hit KeyError: {e} while extracting serial number " +
                  f"of {node}")
            continue
        if not ser_num:
            errcnt += 1
            print(f"{ERROR} Cannot extract serial number of {node}")
            continue
        if ser_num in ser_nums:
            duplicate_cnt += 1
        else:
            ser_nums.append(ser_num)
        ser_num_kv[node] = ser_num
    if errcnt != 0:
        return errcnt

    if duplicate_cnt == 0:
        print(f"{INFO} All nodes have unique serial number")
        return 0

    errcnt += duplicate_cnt
    print(f"{ERROR} All nodes have {duplicate_cnt} duplicate serial number")
    for k, v in ser_num_kv.items():
        print(f"{WARN} Serial number of {k} is {2}".format(WARN, k, v))
    return errcnt


def main():
    """Main entrance.
    Args:
    Returns:
    """
    json_files, json_dir, skip_check = parse_arguments()
    errmsg = "Installation terminated. Please try to resolve the problem " + \
             "or contact IBM\n"
    print(f"{INFO} IBM Storage Scale Erasure Code Edition (ECE) OS overview " +
          f"version: {MODULE_VER}")
    file_errcnt = check_file_presence(json_dir, json_files)
    if file_errcnt != 0:
        print(f"{ERROR} {errmsg}")
        return file_errcnt

    # Load all the json files into a dictionary
    all_in_one_kv = collect_check_results(json_dir, json_files)
    if not all_in_one_kv:
        print(f"{ERROR} {errmsg}")
        return 1

    if skip_check is True:
        result_file = os.path.join(json_dir, 'all_in_one_result.json')
        outputdata = json.dumps(all_in_one_kv, indent=4)
        try:
            with open(result_file, 'w') as fh:
                fh.write(outputdata)
            print(f"{INFO} Saved all separate check results to {result_file}")
        except BaseException as e:
            print(f"{ERROR} Hit exception: {e} while writing file " +
                  f"{result_file}")
        print(f"{WARN} No overview check performed. Installation terminated\n")
        return 1

    print(f"{INFO} Summarize separate storage server checks")
    top_errcnt = review_top_conclusions(json_files, all_in_one_kv)
    if top_errcnt != 0:
        print(f"{ERROR} {errmsg}".format(ERROR, errmsg))
        return top_errcnt

    falal_error_cnt = 0
    # Check OS architecture
    proc_errcnt = check_processor_name(json_files, all_in_one_kv)
    falal_error_cnt += proc_errcnt

    # Check number of CPU socket
    sock_errcnt = check_cpu_socket(json_files, all_in_one_kv)
    falal_error_cnt += sock_errcnt

    # Check number of CPU cores per socket
    core_errcnt = check_cpu_core(json_files, all_in_one_kv)
    falal_error_cnt += core_errcnt

    # Check vacant DIMM slot number
    dimm_errcnt = check_populated_dimm_slot_number(json_files, all_in_one_kv)
    falal_error_cnt += dimm_errcnt

    # Check system memory size
    mem_size_errcnt = check_memory_size(json_files, all_in_one_kv)
    falal_error_cnt += mem_size_errcnt

    # Check Network controller
    net_ctrlr_errcnt = check_net_controller(json_files, all_in_one_kv)
    falal_error_cnt += net_ctrlr_errcnt

    if net_ctrlr_errcnt == 0:
        # Check network interface link speed
        net_speed_errcnt = check_netif_speed(json_files, all_in_one_kv)
        falal_error_cnt += net_speed_errcnt

    # Check SCSI controller
    scsi_ctrlr_errcnt = check_scsi_controller(json_files, all_in_one_kv)
    falal_error_cnt += scsi_ctrlr_errcnt

    # Check NVMe drive
    nvme_errcnt, ttl_nvme_num = count_number_of_disk_by_devtype(
                                   json_files,
                                   all_in_one_kv,
                                   'NVMe')
    falal_error_cnt += nvme_errcnt
    if nvme_errcnt == 0 and ttl_nvme_num >= MIN_DEV_NUM_PER_DA:
        # Check if NVMes have different euids or nguids
        nvme_id_errcnt = check_nvme_id(json_files, all_in_one_kv)
        falal_error_cnt += nvme_id_errcnt

    # Check SSD
    ssd_errcnt, ttl_ssd_num = count_number_of_disk_by_devtype(
                                  json_files,
                                  all_in_one_kv,
                                  'SSD')
    falal_error_cnt += ssd_errcnt
    if ssd_errcnt == 0 and ttl_ssd_num >= MIN_DEV_NUM_PER_DA:
        ssd_wwn_errcnt = check_storage_device_wwn(
                             json_files,
                             all_in_one_kv,
                             'SSD')
        falal_error_cnt += ssd_wwn_errcnt

    # Check HDD
    hdd_errcnt, ttl_hdd_num = count_number_of_disk_by_devtype(
                                  json_files,
                                  all_in_one_kv,
                                  'HDD')
    falal_error_cnt += hdd_errcnt
    if hdd_errcnt == 0 and ttl_hdd_num >= MIN_DEV_NUM_PER_DA:
        hdd_wwn_errcnt = check_storage_device_wwn(
                             json_files,
                             all_in_one_kv,
                             'HDD')
        falal_error_cnt += hdd_wwn_errcnt
    is_da_valid = any(n >= MIN_DEV_NUM_ALO_DA for n in [
                      ttl_nvme_num,
                      ttl_ssd_num,
                      ttl_hdd_num])
    if is_da_valid is False:
        falal_error_cnt += 1
        print(f"{ERROR} At least one declustered array (DA) must contain " +
              f"{MIN_DEV_NUM_ALO_DA} or more drives")

    # Check all storage devices
    all_dev_errcnt = check_all_valid_storage_device_number(
                                      json_files,
                                      all_in_one_kv)
    falal_error_cnt += all_dev_errcnt

    # Check system serial numbers
    ser_num_errcnt = check_system_serial_number(json_files, all_in_one_kv)
    falal_error_cnt += ser_num_errcnt

    print(f"{INFO} ECE overview checks are completed".format(INFO))
    if falal_error_cnt == 0:
        print(f"{INFO} All ECE overview checks passed. Installation continues")
    else:
        print(f"{ERROR} Not all ECE overview checks passed. Installation " +
              "stopped")

    return falal_error_cnt


if __name__ == '__main__':
    sys.exit(main())
