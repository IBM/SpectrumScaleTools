#!/usr/bin/python
import json
import argparse
import csv
import os
import sys
import ast
import platform

MOR_OVERVIEW_VERSION = "1.8"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

# Message labels
INFO = "[ " + GREEN + "INFO" + NOCOLOR + "  ] "
WARNING = "[ " + YELLOW + "WARN" + NOCOLOR + "  ] "
ERROR = "[ " + RED + "FATAL" + NOCOLOR + " ] "

# GB of difference between nodes in the same RG
GB_DIFF_NODES = 6


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('--json-files',
                        required=True,
                        action='store',
                        dest='json_files_csv_str',
                        help='CSV JSON list of files to process',
                        metavar='JSON_CSV_FILES_LIST',
                        type=str)

    parser.add_argument('--no-checks',
                        action='store_false',
                        dest='do_checks',
                        help='Does not run any checks, just ' +
                        'loads the files and continues',
                        default=True)

    parser.add_argument('--path',
                        action='store',
                        dest='path',
                        help='Path ending with / where JSON files ' +
                        'are located. Defaults to local directory',
                        metavar='PATH/',
                        type=str,
                        default='./')

    parser.add_argument('-v',
                        '--version',
                        action='version',
                        version='IBM Spectrum Scale Erasure Code ' +
                        'Edition OS readiness overview version '
                        + MOR_OVERVIEW_VERSION)

    args = parser.parse_args()

    return args.json_files_csv_str, args.path, args.do_checks


def convert_csv_string_into_list(csv_string):
    # We have no header
    # we expect a single line passed by the toolkit with filenames
    csv_files_list = csv_string.split(",")
    return csv_files_list


def files_exists(json_files_path, json_files_list):
    # Lets check the files do actually exists
    for json_file in json_files_list:
        if os.path.isfile(json_files_path + json_file):
            pass
        else:
            sys.exit(
                ERROR +
                " cannot find file: " +
                json_files_path + json_file)


def load_json_files_into_ditionary(json_files_path, json_files_list):
    # We might have up to 64 or 128 files loaded into memory
    all_json_dict = {}
    # If we cannot load a file, if not right format we need to fail hard
    try:
        for json_file in json_files_list:
            json_file_name = open(json_files_path + json_file, 'r')
            all_json_dict[json_file] = ast.literal_eval(json.load(json_file_name))
        return all_json_dict
    except BaseException:
        sys.exit(
            ERROR +
            " cannot load JSON file: " +
            json_files_path + json_file)


def unique_list(inputlist):
    outputlist = []
    for item in inputlist:
        if item not in outputlist:
            outputlist.append(item)
    return outputlist


def review_individual_checks(json_files_list, all_json_dict):
    # We have a dictionary with JSON file names as index
    # and lots of good information from each node
    errors = 0
    for node_file in json_files_list:
        can_run_ECE = all_json_dict[node_file]['ECE_node_ready']
        hostname = all_json_dict[node_file]['local_hostname']
        IP_address = all_json_dict[node_file]['ip_address']
        # This has been already checked by the toolkit at this point
        # valid_IP_address = all_json_dict[node_file]['IP_address_is_possible']
        if can_run_ECE:
            print(INFO + " " + hostname + " with IP address " + IP_address +
                  " passed the individual ECE checks")
        else:
            print(ERROR + " " + hostname + " with IP address " + IP_address +
                  " did not pass the individual ECE checks and cannot run ECE")
            errors = errors + 1
    return errors


def check_different_serial_on_nodes(
        json_files_list,
        all_json_dict):
    if platform.processor() == 's390x':  # No serial# checking on s390x
        return 0
    errors = 0
    tmp_list = []
    for node_file in json_files_list:
        try:
            item = all_json_dict[node_file]["system_serial"]
            if item in tmp_list:
                errors = errors +1
            else:
                tmp_list.append(item)
        except KeyError:
            # No key on JSON lets not fail here
            tmp_list.append(False)
        if errors > 0:
            # we have duplicates
            duplicates_error = True
        else:
            duplicates_error = False
    return duplicates_error


def check_different_wwn_on_nodes(
        json_files_list,
        all_json_dict,
        dict_json_index):

    errors = 0
    tmp_list = []
    for node_file in json_files_list:
        try:
            for drive in all_json_dict[node_file][dict_json_index].keys():
                item = all_json_dict[node_file][dict_json_index][drive][4]
                if item in tmp_list:
                    errors = errors +1
                else:
                    tmp_list.append(item)
        except KeyError:
            # No key on JSON lets not fail here
            tmp_list.append(False)
    if errors > 0:
        # we have duplicates
        duplicates_error = True
    else:
        duplicates_error = False
    return duplicates_error

def check_different_nvme_id_on_nodes(
        json_files_list,
        all_json_dict,
        dict_json_index):
    errors = 0
    eui_list = []
    nguid_list = []
    eui_zero = '0000000000000000'
    nguid_zero = '00000000000000000000000000000000'
    for node_file in json_files_list:
        try:
            for drive in all_json_dict[node_file][dict_json_index].keys():
                eui = all_json_dict[node_file][dict_json_index][drive][0]
                nguid = all_json_dict[node_file][dict_json_index][drive][1]

                if str(eui) != eui_zero and str(eui) in eui_list:
                    errors = errors +1
                else:
                    eui_list.append(str(eui))

                if str(nguid) != nguid_zero and str(nguid) in nguid_list:
                    errors = errors +1
                else:
                    nguid_list.append(str(nguid))
        except KeyError:
            # No key on JSON lets not fail here
            eui_list.append(False)
            nguid_list.append(False)

    if errors > 0:
        # we have duplicates
        duplicates_error = True
    else:
        duplicates_error = False
    return duplicates_error

def check_same_values_on_nodes(
        json_files_list,
        all_json_dict,
        dict_json_index):
    errors = 0
    tmp_list = []
    for node_file in json_files_list:
        try:
            item = all_json_dict[node_file][dict_json_index]
            tmp_list.append(item)
        except KeyError:
            # No key on JSON lets not fail here
            tmp_list.append(False)
    values_list = unique_list(tmp_list)
    if len(values_list) != 1:
        errors = errors + 1
    return errors


def sum_values_on_nodes(json_files_list, all_json_dict, dict_json_index):
    total_sum = 0
    for node_file in json_files_list:
        total_sum = total_sum + all_json_dict[node_file][dict_json_index]
    return total_sum


def check_system_loose_memory(json_files_list, all_json_dict, dict_json_index):
    system_loose_memory_error = False
    # Lets give some room for differences on system memory between nodes
    list = []
    for node_file in json_files_list:
        item = all_json_dict[node_file][dict_json_index]
        list.append(item)
    min_system_mem = min(list)
    max_system_mem = max(list)
    if max_system_mem - min_system_mem > GB_DIFF_NODES:
        system_loose_memory_error = True
    return system_loose_memory_error


def print_summary(
            arch_errors,
            socket_errors,
            core_errors,
            dimm_all_slots_error,
            dimm_empty_slots_error,
            system_memory_error,
            system_loose_memory_error,
            NIC_errors,
            link_errors,
            SAS_errors,
            NVME_fatal_errors,
            NVME_num_errors,
            NVME_not_available,
            NVME_number_of_drives,
            NVME_duplicate_id_error,
            SSD_fatal_errors,
            SSD_num_errors,
            SSD_not_available,
            SSD_number_of_drives,
            SSD_wwn_duplicated,
            HDD_fatal_errors,
            HDD_num_errors,
            HDD_not_available,
            HDD_number_of_drives,
            HDD_wwn_duplicated,
            ALL_number_of_drives,
            node_duplicated_serial
            ):

    fatal_errors = 0

    if arch_errors == 0:
        print(INFO + " All ECE nodes have the same processor architecture")
    else:
        print(
            ERROR +
            " Not all ECE nodes have the same " +
            "processor architecture")
        fatal_errors = fatal_errors + 1

    if platform.processor() != 's390x':  # No sockets on s390x
        if socket_errors == 0:
            print(INFO + " All ECE nodes have the same number of sockets")
        else:
            print(ERROR + " Not all ECE nodes have the same number of sockets")
            fatal_errors = fatal_errors + 1

    if core_errors == 0:
        if platform.processor() == 's390x':  # No sockets on s390x
            print(INFO + " All ECE nodes have the same number of cores")
        else:
            print(INFO + " All ECE nodes have the same number of cores per socket")
    else:
        if platform.processor() == 's390x':  # No sockets on s390x
            print(ERROR + " Not all ECE nodes have the same " +
                  "number of cores")
        else:
            print(ERROR + " Not all ECE nodes have the same " +
                  "number of cores per socket")
        fatal_errors = fatal_errors + 1

    if platform.processor() != 's390x':  # No dimms on s390x
        if dimm_all_slots_error == 0 and dimm_empty_slots_error == 0:
            print(INFO + " All ECE nodes have the same number " +
                  "DIMM slots and modules")
        else:
            print(
                WARNING +
                " Not all ECE nodes have the same number " +
                " DIMM slots and modules")

    if system_memory_error == 0:
        print(INFO + " All ECE nodes have the same system memory")
    else:
        if system_loose_memory_error:
            print(ERROR + " Not all ECE nodes have the same system memory")
            fatal_errors = fatal_errors + 1
        else:
            print(
                WARNING +
                " Not all ECE nodes have the same system memory, " +
                "but the differences are within acceptable range of +/- " +
                str(GB_DIFF_NODES) + " GBytes")

    if NIC_errors == 0:
        print(INFO + " All ECE nodes have the same NIC model")
    else:
        print(ERROR + " Not all ECE nodes have the same NIC model")
        fatal_errors = fatal_errors + 1

    if link_errors == 0:
        print(INFO + " All ECE nodes have the same network link speed")
    else:
        print(ERROR + " Not all ECE nodes have the same network link speed")
        fatal_errors = fatal_errors + 1

    if platform.processor() != 's390x':  # No SAS drives on s390x
        if SAS_errors == 0:
            print(INFO + " All ECE nodes have the same SAS model")
        else:
            print(ERROR + " Not all ECE nodes have the same SAS model")
            fatal_errors = fatal_errors + 1

    if NVME_fatal_errors == 0:
        print(
            INFO +
            " All ECE nodes have NVMe drives or all ECE " +
            "nodes have no NVMe drives")
    else:
        print(
            ERROR +
            " Some ECE nodes have NVMe drives and other ECE " +
            "nodes do not have NVMe drives")
        fatal_errors = fatal_errors + 1

    if NVME_num_errors == 0:
        print(INFO + " All ECE nodes have the same number of NVMe drives")
    else:
        print(ERROR + " Not all ECE nodes have the same number of NVMe drives")
        fatal_errors = fatal_errors + 1

    if not NVME_not_available:
        if NVME_number_of_drives > 5:
            print(
                INFO +
                " There are " +
                str(NVME_number_of_drives) +
                " NVMe drive[s] that can be used by the ECE cluster")
        else:
            print(
                ERROR + " There are " +
                str(NVME_number_of_drives) +
                " NVMe drive[s] that can be used by the ECE cluster")
            fatal_errors = fatal_errors + 1
    else:
        print(INFO + " There are no NVMe drives that can be used by ECE")

    if NVME_duplicate_id_error:
        print(ERROR + " Some ECE nodes have NVMe drives that have identical euids/nguids.")
        fatal_errors = fatal_errors + 1
    else:
        print(INFO + " All ECE nodes have NVMe drives that have unique euids/nguids.")

    if platform.processor() != 's390x':  # No SSDs on s390x
        if SSD_fatal_errors == 0:
            print(INFO + " All ECE nodes have SSD drives or " +
                  "all ECE nodes have no SSD drives")
        else:
            print(ERROR + " Some ECE nodes have SSD drives and " +
                  "other ECE nodes do not have SSD drives")
            fatal_errors = fatal_errors + 1
   
        if SSD_num_errors == 0:
            print(INFO + " All ECE nodes have the same number of SSD drives")
        else:
            print(ERROR + " Not all ECE nodes have the same number of SSD drives")
            fatal_errors = fatal_errors + 1

        if not SSD_not_available:
            if SSD_number_of_drives > 5:
                print(INFO + " There are " +
                      str(SSD_number_of_drives) +
                      " SSD drive[s] that can be used by the ECE cluster")
            else:
                print(ERROR + " There are "
                      + str(SSD_number_of_drives) +
                      " SSD drive[s] that can be used by the ECE cluster")
                fatal_errors = fatal_errors + 1
            if SSD_wwn_duplicated:
                print(ERROR + " There are duplicated WWN on the SSD drives")
                fatal_errors = fatal_errors + 1
            else:
                print(INFO + " There are no duplicated WWN on the SSD drives")
        else:
            print(INFO + " There are no SSD drives that can be used by ECE")

    if platform.processor() != 's390x':  # No HDD on s390x
        if HDD_fatal_errors == 0:
            print(INFO + " All ECE nodes have HDD drives or " +
                  "all ECE nodes have no HDD drives")
        else:
            print(ERROR + " Some ECE nodes have HDD drives and " +
                  "other ECE nodes do not have HDD drives")
            fatal_errors = fatal_errors + 1

        if HDD_num_errors == 0:
            print(INFO + " All ECE nodes have the same number of HDD drives")
        else:
            print(ERROR + " Not all ECE nodes have the same number of HDD drives")
            fatal_errors = fatal_errors + 1

        if not HDD_not_available:
            if HDD_number_of_drives > 5:
                print(
                    INFO +
                    " There are " +
                    str(HDD_number_of_drives) +
                    " HDD drive[s] that can be used by the ECE cluster")
            else:
                print(
                    ERROR +
                    " There are " +
                    str(HDD_number_of_drives) +
                    " HDD drive[s] that can be used by the ECE cluster")
                fatal_errors = fatal_errors + 1
            if HDD_wwn_duplicated:
                print(ERROR + " There are duplicated WWN on the HDD drives")
                fatal_errors = fatal_errors + 1
            else:
                print(INFO + " There are no duplicated WWN on the HDD drives")
        else:
            print(INFO + " There are no HDD drives that can be used by ECE")

    # Do we have 12 drives or more from any type of drive?
    if any(x > 11 for x in (NVME_number_of_drives,SSD_number_of_drives,HDD_number_of_drives)):
        print(
            INFO +
            " There are 12 or more drives of one technology" +
            " that can be used by the ECE cluster")
    else:
        print(
            ERROR +
            " There are not 12 drives of one technology" +
            " that can be used by the ECE cluster. At least 12 drives of" +
            " one type is mandatory to create one RG")
        fatal_errors = fatal_errors + 1

    if ALL_number_of_drives < 513:
        print(
            INFO +
            " There are " +
            str(ALL_number_of_drives) +
            " drive[s] that can be used by the ECE cluster, " +
            "the maximum number of drives per Recovery Group is 512")
    else:
        print(
            WARNING +
            " There are " +
            str(ALL_number_of_drives) +
            " drive[s] that can be used by the ECE cluster, " +
            "the maximum number of drives per Recovery Group is 512. " +
            "You must use more than one Recovery Group")
    if platform.processor() != 's390x':  # No serial# checking on s390x
        if node_duplicated_serial:
            print(
                ERROR +
                " Not all nodes have unique serial numbers")
            fatal_errors = fatal_errors + 1
        else:
            print(
                INFO +
                " All nodes have unique serial numbers")
        

    if fatal_errors > 0:
        sys.exit(
            ERROR +
            " Not all ECE checks passed, " +
            "check output and mitigate those issues before trying again")
    else:
        print(INFO + " All ECE checks passed, installation can continue")

def main():
    json_files_csv_str, json_files_path, do_checks = parse_arguments()

    # We have a CSV list of files to open and compare for key elements
    json_files_list = convert_csv_string_into_list(json_files_csv_str)

    # If toolkig passes us a wrong list, then there is something really wrong
    files_exists(json_files_path, json_files_list)

    # Lets load all the JSON files into a dictionary
    all_json_dict = load_json_files_into_ditionary(json_files_path,
                                                   json_files_list)

    # Lets compare the key settings
    if do_checks:
        print(INFO + " Starting summary of individual ECE checks")
        # Lets see if some node did not pass the individual ECE checks
        individual_errors = review_individual_checks(
            json_files_list,
            all_json_dict)
        if individual_errors > 0:
            # Toolkit needs to raise an problem here
            sys.exit(
                ERROR +
                " Individual ECE checks failed on " +
                str(individual_errors) +
                " node[s], those cannot run ECE. Please check the output of " +
                "individual checks of those nodes for details. " +
                "Installation cannot continue")
        else:
            print(
                INFO +
                " Individual ECE checks passed on all configured ECE nodes")
        # We now start doing the overall tests
        print(
            INFO +
            " Starting overall ECE checks version " +
            MOR_OVERVIEW_VERSION)
        # Lets check all nodes have same architecture
        # likely toolkit might have already check this
        arch_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'current_processor')
        # Lets check all nodes have same number of sockets
        socket_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'num_sockets')
        # Lets check it has the same number of cores per socket
        core_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'cores_per_socket')
        # Check DIMM slots are the same on all nodes, just WARNING if not
        dimm_all_slots_error = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'num_dimm_slots')
        dimm_empty_slots_error = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'num_dimm_empty_slots')
        # Lets check system memory is the same
        system_memory_error = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'system_memory')
        # We should allow some differences on the total system memory reported
        system_loose_memory_error = check_system_loose_memory(
            json_files_list,
            all_json_dict,
            'system_memory')
        # Check NIC model is the same in all nodes
        NIC_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'NIC_model')
        # Check link speed is the same in all nodes
        link_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'netdev_speed')

        # Check SAS model is the same in all nodes
        SAS_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'SAS_model')
        # Check all nodes have same NVME_fatal_error status
        NVME_fatal_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'NVME_fatal_error')
        # Check NVME_number_of_drives is the same in all nodes
        # is a finer check than only NVME_fatal_error
        NVME_num_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'NVME_number_of_drives')
        # Lets check we have at least 6 NVMe drives, we passed
        # check_same_values_on_nodes so we can just query any node
        try:
            NVME_not_available = list(all_json_dict.values())[0]['NVME_fatal_error']
        except KeyError:
            NVME_not_available = True
        NVME_number_of_drives = 0
        if not NVME_not_available:
            NVME_number_of_drives = sum_values_on_nodes(
                json_files_list,
                all_json_dict,
                'NVME_number_of_drives')

        #Check to see if any Nvmes have identical euids or nguids
        NVME_duplicate_id_error = check_different_nvme_id_on_nodes(
            json_files_list,
            all_json_dict,
            'NVME_ID')

        # Check all nodes have same SSD_fatal_error status
        SSD_fatal_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'SSD_fatal_error')
        # Check SSD_number_of drives is the same in all nodes
        # is a finer check than only SSD_fatal_error
        SSD_num_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'SSD_n_of_drives')
        # Lets check we have at least 6 SSD drives
        # we passed check_same_values_on_nodes so we can just query any node
        try:
            SSD_not_available = list(all_json_dict.values())[0]['SSD_fatal_error']
        except KeyError:
            SSD_not_available = True
        SSD_number_of_drives = 0
        SSD_wwn_duplicated = False
        if not SSD_not_available:
        #if not SSD_fatal_errors:
            SSD_number_of_drives = sum_values_on_nodes(
                json_files_list,
                all_json_dict,
                'SSD_n_of_drives')
            SSD_wwn_duplicated = check_different_wwn_on_nodes(
                json_files_list,
                all_json_dict,
                'SSD_drives')
        # Check all nodes have same HDD_fatal_error status
        HDD_fatal_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'HDD_fatal_error')
        # Check HDD_number_of_drives is the same in all nodes
        # is a finer check than only HDD_fatal_error
        HDD_num_errors = check_same_values_on_nodes(
            json_files_list,
            all_json_dict,
            'HDD_n_of_drives')
        # Lets check we have at least 6 HDD drives
        # we passed check_same_values_on_nodes so we can just query any node
        try:
            HDD_not_available = list(all_json_dict.values())[0]['HDD_fatal_error']
        except KeyError:
            HDD_not_available = True
        HDD_number_of_drives = 0
        HDD_wwn_duplicated = False
        if not HDD_not_available:
        #if not HDD_fatal_errors:
            HDD_number_of_drives = sum_values_on_nodes(
                json_files_list,
                all_json_dict,
                'HDD_n_of_drives')
            HDD_wwn_duplicated = check_different_wwn_on_nodes(
                json_files_list,
                all_json_dict,
                'HDD_drives')
        # Could leverage sum of the amounts calculated here
        # but lets use the JSON input instead
        ALL_number_of_drives = sum_values_on_nodes(
            json_files_list,
            all_json_dict,
            'ALL_number_of_drives')

        # Check unique serial numbers
        node_duplicated_serial = check_different_serial_on_nodes(
            json_files_list,
            all_json_dict
        )
        # We are done with checks
        print(INFO + " Completed overall ECE checks")

        # Lets print the results and RC=1 if any issues
        print_summary(
            arch_errors,
            socket_errors,
            core_errors,
            dimm_all_slots_error,
            dimm_empty_slots_error,
            system_memory_error,
            system_loose_memory_error,
            NIC_errors,
            link_errors,
            SAS_errors,
            NVME_fatal_errors,
            NVME_num_errors,
            NVME_not_available,
            NVME_number_of_drives,
            NVME_duplicate_id_error,
            SSD_fatal_errors,
            SSD_num_errors,
            SSD_not_available,
            SSD_number_of_drives,
            SSD_wwn_duplicated,
            HDD_fatal_errors,
            HDD_num_errors,
            HDD_not_available,
            HDD_number_of_drives,
            HDD_wwn_duplicated,
            ALL_number_of_drives,
            node_duplicated_serial
            )
    else:
        print(
            WARNING +
            " No overall ECE checks performed, " +
            "this is not the expected way to run this ECE check. " +
            "Run it this way only for test purpouses")


if __name__ == '__main__':
    main()
