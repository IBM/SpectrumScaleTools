#!/usr/bin/env python3
'''
gnr_capacity_estimator - estimate usable file system capacity for a given
IBM Storage Scale RAID configuration.

This tool implements the tsgnrplan logic in python so it can be executed on
system where python is installed.
'''

import argparse
import sys
import math
import json


# This script version, independent from the JSON versions
GCE_VERSION = "1.3"

# GIT URL
GITREPOURL = "https://github.com/IBM/SpectrumScaleTools"

# Example tsgnrplan invocation:
# tsgnrplan --nodes 4 --min-nodes 4 --max-nodes 4 --log-groups-per-node 2
#           --pdisks-per-node 3 --pdisk-size 402384748544
#           --au-log-size 3221225472 --log-home-vdisk-size 2684354560
#           --pdisks-per-spare 6 --spare-nodes 0 --prior-vdisk-raw-size 0
#           --vdisk-set-size 100% --code 4+2p --track-size 4M

# minimum node count
MIN_NODE_COUNT = 2

# see ts/vdisk/tsgnrplan.C
LOGHOME_REPLICAS = 4.0
LOGGROUPS_PER_NODE = 2

# see ts/vdisk/GNRDisk.h
RG_DESC1_HIGH_RESERVED_SLOT = 16
MD_SLOT_SIZE = 256*1024
PDISK_MAX_OVFL_PARTS = 4
MIN_PDISK_PARTITION_SIZE = 4.0 * 1024 * 1024
UNASSIGNED_PTRACK_DIVISOR = 1000
EXPANDED_MAX_UNASSIGNED_PTRACKS = 4096
MIN_UNASSIGNED_PTRACKS = 32
MAX_PDISK_PARTITIONS = 2048

# see ts/classes/basic/Shark.h
GPFS_4K_SECTOR_SIZE = 4096

# see ts/vdisk/VdiskTypes.h
DISK_ALIGNMENT_BYTES = 4096

VALID_CODES = {'4+2p': (4, 2),
               '4+3p': (4, 3),
               '8+2p': (8, 2),
               '8+3p': (8, 3),
               '16+2p': (16, 2),
               '16+3p': (16, 3)}

# block size in MiB
VALID_BLOCKSIZES = [1, 2, 4, 8, 16]
VALID_DISKTYPES = ['hdd', 'ssd']

DEBUG = False

CONVERT_DICT = {'KiB': 1,
                'MiB': 2,
                'GiB': 3,
                'TiB': 4}


def show_header():
    print("")
    print(
        "IBM Storage Scale RAID Estimator version " +
        GCE_VERSION)
    print("This tool comes with no warranty of any kind")
    print("")
    print("Please check " + GITREPOURL + " for updates and other information")
    print("")


# convert from bytes to units
def fromb(value, units):
    n = CONVERT_DICT[units]
    return int(value/(1024**n))


# convert to bytes from a value in units
def tob(value, units):
    n = CONVERT_DICT[units]
    return value * (1024**n)


# convert from bytes to TB (decimal)
def btotb(bytes):
    return float(bytes)/(1000**4)


# for ECE see /usr/lpp/mmfs/data/cst/compSpec-scaleOut.stanza
# todo: support ESS value
AULOGSZ = tob(3, 'GiB')    # 3221225472
ROOTLOGHOMESZ = tob(2, 'GiB')  # 34359738368
USERLOGHOMESZ = tob(32, 'GiB')  # 34359738368


# see perseus wiki - add link
def calc_spares(nodes, pdisksPerNode):
    nds = int(nodes)
    pdisks = int(pdisksPerNode)
    if pdisks == 1:
        smin = 2
        smax = 4 * pdisks
        nmax = 24
    elif pdisks < 5:
        smin = 2
        smax = 2 * pdisks
        nmax = 16
    else:
        smin = 3
        smax = 2 * pdisks
        nmax = 4 * pdisks
    if nds > nmax:
        spares = smax
    else:
        spares = (smax * nds) / nmax
        if spares < smin:
            spares = smin

    return spares


# see ts/mmfsd/sharkd.C
def ROUNDUP(X, Y):
    X = math.ceil(X)
    Y = int(Y)
    return int((Y) * int(((X)+(Y)-1) / float(Y)))


# see ts/classes/basic/Shark.h
def DIVROUND(X, Y):
    X = int(X)
    Y = int(Y)
    return int(((X)+(Y)-1) / (Y))


def logdbg(msg):
    if DEBUG:
        if len(msg) > 0:
            print('DEBUG: {}'.format(msg))
        else:
            print('')


def get_checksum_granularity(blocksize, code, disktype):
    cg = tob(32, 'KiB')
    if disktype in ['ssd']:
        if code in ['8+2p', '8+3p']:
            if blocksize <= 4:
                cg = tob(8, 'KiB')
        elif code in ['4+2p', '4+3p']:
            if blocksize <= 2:
                cg = tob(8, 'KiB')
    return cg


# See ts/vdisk/tsgnrplan.C
def get_gnrplan(nNodes, disksPerNode, sparePdisks, pdiskSize,
                vdiskTrackSize,
                dataStripsPerTrack, parityStripsPerTrack,
                checksumGranularity, nologhomes, setSize):

    # intermediate variable names for debug output
    debug_names = ['pdiskEndReserved', 'partitionSize', 'partitionsPerPdisk',
                   'pdiskPrefixPartitions', 'overflowPartitions',
                   'totalPdisks', 'totalPartitions', 'reservedPartitions',
                   'maxLogGroups', 'rootLogHomeSize', 'userLogHomeSize', 'adjustedLoghomeSize',
                   'partitionsPerLogHomeVdisk', 'nonLogUsablePartitions',
                   'nonLogUsablePartitionsPerLG', 'nonLogPartitionsUsedPerLG',
                   'partitionsAvailablePerLG', 'targetRawPartitionsPerVdisk',
                   'partitionGroupsPerVdisk', 'rawPartitionsPerVdisk',
                   'diskSegmentSize', 'vdiskTrackSize', 'dataBytesPerStrip',
                   'diskSegmentsPerStrip', 'rawBytesPerStrip',
                   'tracksPerPG', 'ptracksPerVdisk', 'nUnassignedTracks',
                   'vdiskDataSize', 'vdiskRawSize', 'pdiskSize']

    rootLogHomeSize = ROOTLOGHOMESZ
    userLogHomeSize = USERLOGHOMESZ
    if nologhomes:
        rootLogHomeSize = 0
        userLogHomeSize = 0

    # from ts/vdisk/tsgnrplan.C
    pdiskEndReserved = get_pdisk_end_reserved(pdiskSize)

    partitionSize = MIN_PDISK_PARTITION_SIZE
    partitionsPerPdisk = float(pdiskSize - pdiskEndReserved) / partitionSize
    while partitionsPerPdisk > MAX_PDISK_PARTITIONS:
        partitionSize = 2 * partitionSize
        partitionsPerPdisk = float(pdiskSize-pdiskEndReserved) / partitionSize

    partitionsPerPdisk = int(partitionsPerPdisk)

    pdiskPrefixPartitions = DIVROUND(float(((RG_DESC1_HIGH_RESERVED_SLOT + 1) *
                                            MD_SLOT_SIZE) + AULOGSZ),
                                     partitionSize)

    overflowPartitions = PDISK_MAX_OVFL_PARTS

    reservedSpaceDivisor = 1000
    totalPdisks = pdisksPerNode * nNodes
    totalPartitions = float(partitionsPerPdisk * totalPdisks)
    reservedPartitions = DIVROUND(totalPartitions, reservedSpaceDivisor)
    maxLogGroups = float(nNodes * LOGGROUPS_PER_NODE)
    fudge = float(rootLogHomeSize) / float(nNodes)
    adjustedLoghomeSize = int(userLogHomeSize) + int(math.ceil(fudge))
    partitionsPerLogHomeVdisk = (LOGHOME_REPLICAS *
                                 DIVROUND(float(adjustedLoghomeSize),
                                          partitionSize))

    nonLogUsablePartitions = (
        totalPartitions -
        (reservedPartitions +
         (totalPdisks - sparePdisks) *
         (pdiskPrefixPartitions + overflowPartitions) +
         sparePdisks * partitionsPerPdisk +
         (maxLogGroups * partitionsPerLogHomeVdisk)))
    nonLogRawVdiskBytesUsed = 0
    nonLogUsablePartitionsPerLG = int(nonLogUsablePartitions / maxLogGroups)
    nonLogPartitionsUsedPerLG = nonLogRawVdiskBytesUsed / partitionSize
    partitionsAvailablePerLG = (nonLogUsablePartitionsPerLG -
                                nonLogPartitionsUsedPerLG)

    targetRawPartitionsPerVdisk = nonLogUsablePartitionsPerLG * (setSize / 100) #--set-size = 10..100
    partitionGroupsPerVdisk = int(targetRawPartitionsPerVdisk /
                                  (dataStripsPerTrack + parityStripsPerTrack))
    rawPartitionsPerVdisk = (partitionGroupsPerVdisk *
                             (dataStripsPerTrack + parityStripsPerTrack))
    segmentTrailerSize = 64  # sizeof(BufferTrailer), see GNRDisk.h
    diskSegmentSize = checksumGranularity
    dataBytesPerStrip = int(vdiskTrackSize / dataStripsPerTrack)
    diskSegmentsPerStrip = DIVROUND(dataBytesPerStrip,
                                    (diskSegmentSize-segmentTrailerSize))
    rawBytesPerStrip = (dataBytesPerStrip +
                        ROUNDUP(diskSegmentsPerStrip*segmentTrailerSize,
                                DISK_ALIGNMENT_BYTES))
    tracksPerPG = int(partitionSize / rawBytesPerStrip)
    ptracksPerVdisk = partitionGroupsPerVdisk * tracksPerPG
    nUnassignedTracks = max(MIN_UNASSIGNED_PTRACKS,
                            min(EXPANDED_MAX_UNASSIGNED_PTRACKS,
                                DIVROUND(ptracksPerVdisk,
                                         UNASSIGNED_PTRACK_DIVISOR)))
    vdiskDataSize = (ptracksPerVdisk - nUnassignedTracks) * vdiskTrackSize
    vdiskRawSize = rawPartitionsPerVdisk * partitionSize

    logdbg('')
    logdbg('Summary of internal variables:')
    logdbg(30 * '-')
    for value in sorted(debug_names):
        logdbg('{:<27} {:>29}'.format(value, eval(value)))

    dataDisks = totalPdisks - sparePdisks
    print('')
    logdbg('Summary of partition usage:')
    logdbg(28 * '-')
    logdbg('Total partitions:                            {:>12.0f}'.
           format((totalPartitions)))
    logdbg('  Reserved partitions:                         {:>10n}'.
           format(reservedPartitions))
    logdbg('  Prefix partitions on data pdisks:            {:>10n}'.
           format(dataDisks * pdiskPrefixPartitions))
    logdbg('  Overflow partitions on data pdisks:          {:>10n}'.
           format(dataDisks * overflowPartitions))
    logdbg('  Spare partitions:                            {:>10n}'.
           format(sparePdisks * partitionsPerPdisk))
    logdbg('  Partitions for all loghome vdisks:         {:>12.0f}'.
           format(maxLogGroups * partitionsPerLogHomeVdisk))
    logdbg('Non log usable partitions:                   {:>12.0f}'.
           format(nonLogUsablePartitions))
    logdbg('  (Total partitions available for data vdisks)')
    logdbg('Partition size (MiB)                           {:>10n}'.
           format(fromb(partitionSize, 'MiB')))
    logdbg('')

    logdbg('Summary of capacity usage:')
    logdbg(28 * '-')
    logdbg('Total raw capacity (GiB):              {:>18.0f}'.
           format(fromb(totalPartitions * partitionSize, 'GiB')))
    logdbg('  Spare capacity (GiB):                {:>18.0f}'.
           format(fromb(sparePdisks * partitionsPerPdisk * partitionSize,
                        'GiB')))
    logdbg('  Aulog, reserved, overflow capacity:  {:>18.0f}'.
           format(fromb((reservedPartitions +
                         dataDisks *
                         (pdiskPrefixPartitions + overflowPartitions)) *
                        partitionSize, 'GiB')))
    logdbg('  Loghome capacity:                    {:>18.0f}'.
           format(fromb(maxLogGroups * partitionsPerLogHomeVdisk *
                        partitionSize, 'GiB')))
    logdbg('  DA capacity:                         {:>18.0f}'.
           format(fromb(nonLogUsablePartitions * partitionSize, 'GiB')))
    logdbg('')

    return (nonLogUsablePartitions, partitionSize, vdiskDataSize, vdiskRawSize)


def get_pdisk_end_reserved(pdisk_size):
    # from ts/stripe/DiskDesc.h
    PaxosAreaSize = 4 * 1024 * 1024
    DiskDescAreaOffset = 12 * GPFS_4K_SECTOR_SIZE
    DiskDescAreaSize = 4 * GPFS_4K_SECTOR_SIZE

    # from ts/vdisk/Pdisk.h
    pdisk_end_reserved = PaxosAreaSize + 2 * (DiskDescAreaOffset +
                                              DiskDescAreaSize)
    return pdisk_end_reserved


def get_input():
    global DEBUG
    parser = argparse.ArgumentParser(description='IBM Storage Scale RAID '
                                                 'Capacity Estimator')
    parser.add_argument('-n', '--node-count',
                        type=int, required=True,
                        help=('Number of storage nodes. For ESS this will '
                              'always be 2. For ECE it should be between '
                              '4 and 32.'))
    parser.add_argument('-p', '--pdisk-per-node',
                        type=int, required=True,
                        help=('Number of identically sized pdisks per '
                              'storage node.'))
    parser.add_argument('-s', '--pdisk-size-gib',
                        type=float, required=False,
                        help='(Optional) Size of each pdisk in GiB '
                             '(2^^30 bytes).')
    parser.add_argument('-t', '--pdisk-size-tb',
                        type=float, required=False,
                        help='Size of each pdisk in TB (decimal).')
    parser.add_argument('-e', '--erasure-code',
                        required=True,
                        help=('Erasure code for vdisks, from {}.'.
                              format(VALID_CODES.keys())))
    parser.add_argument('-b', '--block-size',
                        default=4,
                        help=('Blocksize, in MiB, from {}, (default 4).'.
                              format(VALID_BLOCKSIZES)))
    parser.add_argument('-d', '--disk-type',
                        default='hdd',
                        help=("Disk type, from {}, both NVMe "
                              "and SAS SSD are considered 'ssd' drives "
                              "(default 'hdd').".format(VALID_DISKTYPES)))
    parser.add_argument('-x', '--exclude-loghome-vdisks', action='store_true',
                        default=False,
                        help=('Include loghome vdisks in sizing estimate,  '
                              '(default True).'))
    parser.add_argument('-j', '--json-format', action='store_true',
                        default=False,
                        help=('Output results in json format.'))
    parser.add_argument('--spare-drives',
                        type=int,
                        help=('(Optional) If specified use this value as the '
                              'number of drives of spare capacity rather than '
                              'calculating based on the number of nodes in '
                              'the recovery group.'))
    parser.add_argument('--set-size',
                        type=int,
                        default=100,
                        required=False,
                        help=('(Optional) Specifies the set size of a vdisk set definition. It defaults to 100 per cent. The value passed must be between 10 and 100'))
    parser.add_argument('-v', '--verbose', action='store_true',
                        default=False,
                        help=('Verbose output.'))

    args = parser.parse_args()

    if args.node_count < MIN_NODE_COUNT:
        print('ERROR:  node_count must be {} or greater.  {} is not valid '
              'input.').format(MIN_NODE_COUNT, args.node_count)
        sys.exit(1)
    if (args.node_count * args.pdisk_per_node < 6 and
            not args.exclude_loghome_vdisks):
        print('ERROR:  total drives must be 6 or greater for DA with loghome '
              'vdisks.  {0} nodes and {1} drives per node is not valid input.'.
              format(args.node_count, args.pdisk_per_node))
        sys.exit(1)
    if args.erasure_code not in VALID_CODES:
        print('ERROR:  Invalid erasure code selected.  Valid choices are  {}.'.
              format(VALID_CODES.keys()))
        sys.exit(1)

    args.block_size = int(args.block_size)
    if args.block_size not in VALID_BLOCKSIZES:
        print('ERROR:  Invalid block size selected.  Valid choices are  {}.'.
              format(VALID_BLOCKSIZES))
        sys.exit(1)

    if args.disk_type not in VALID_DISKTYPES:
        print('ERROR: Invalid disk type selected.  Valid choices are  {}.'.
              format(VALID_DISKTYPES))
        sys.exit(1)

    if args.pdisk_size_gib is None and args.pdisk_size_tb is None:
        print('ERROR: No disk size specified.  Use either "--pdisk-size-gib" '
              ' or "--pdisk-size-tb" to input disk size.')
        sys.exit(1)

    if args.pdisk_size_tb is not None:
        if args.pdisk_size_gib is not None:
            print('WARN: Both "--pdisk-size-gib" and "--pdisk-size-tb" were '
                  'specified, will use TB value of {}'.
                  format(args.pdisk_size_tb))
        args.pdisk_size_gib = float(fromb((args.pdisk_size_tb * 1000**4),
                                          'GiB'))

    if args.set_size > 100 or args.set_size < 10:
        print('ERROR: --set-size value must be between 10 and 100')
        sys.exit(1)

    if args.verbose:
        DEBUG = True

    return (args.node_count, args.pdisk_per_node, args.pdisk_size_gib,
            args.block_size, args.erasure_code, args.exclude_loghome_vdisks,
            args.disk_type, args.json_format, args.spare_drives, args.set_size)


if __name__ == '__main__':

    show_header()

    (numNodes, pdisksPerNode, pdiskSize, blocksize, code,
     nologhomes, disktype, jsonfmt, spares, setSize) = get_input()

    logdbg('Starting with debug enabled')

    # checksumGranularity = 32 * 1024
    # checksumGranularity = 8 * 1024
    checksumGranularity = get_checksum_granularity(blocksize, code, disktype)

    # calculate spares unless value is passed as input
    if spares is None:
        spares = calc_spares(numNodes, pdisksPerNode)

    vdiskTrackSize_bytes = tob(blocksize, 'MiB')
    dataStripsPerTrack, parityStripsPerTrack = VALID_CODES[code]
    pdiskSizeTb = btotb(tob(pdiskSize, 'GiB'))

    if not jsonfmt:
        print('Input Parameter Summary:')
        print(24*'-')
        print('Node count:             {:>40d}'.format(numNodes))
        print('Pdisks per node:        {:>40d}'.format(pdisksPerNode))
        print('Erasure code:           {:>40}'.format(code))
        # print('Pdisk size (GiB):       {:>40}'.format(pdiskSize))
        print('Pdisk size (TB):        {:>40.2f}'.format(pdiskSizeTb))
        print('Block size (MiB):       {:>40}'.format(blocksize))
        print('Disk type:              {:>40}'.format(disktype))
        print('Checksum granularity (KiB): {:>36}'.
              format(fromb(checksumGranularity, 'KiB')))
        print('Exclude loghome vdisks? {:>40}'.format(repr(nologhomes)))

    pdiskSize_bytes = tob(pdiskSize, 'GiB')
    gnrplan = get_gnrplan(numNodes, pdisksPerNode, spares, pdiskSize_bytes,
                          vdiskTrackSize_bytes,
                          dataStripsPerTrack, parityStripsPerTrack,
                          checksumGranularity, nologhomes, setSize)

    (nonlog_usable_partitions, partitionSize, vdiskDataSize,
        vdiskRawSize) = gnrplan
    total_pdisk_capacity = numNodes * pdisksPerNode * pdiskSize
    da_capacity = fromb(nonlog_usable_partitions * partitionSize, 'GiB')
    max_fs_capacity = fromb(vdiskDataSize * numNodes * LOGGROUPS_PER_NODE,
                            'GiB')
    max_fs_capacity_tb = btotb(vdiskDataSize * numNodes * LOGGROUPS_PER_NODE)

    if jsonfmt:
        valdict = {'tot_capacity_gib':        int(total_pdisk_capacity),
                   'da_capacity_gib':         int(da_capacity),
                   'vdisk_raw_cap_mib':       fromb(int(vdiskRawSize), 'MiB'),
                   'vdisk_data_cap_mib':      fromb(int(vdiskDataSize), 'MiB'),
                   'vdisk_count':             numNodes * LOGGROUPS_PER_NODE,
                   'file_system_cap_gib':     int(max_fs_capacity)
                   }
        print(json.dumps(valdict))
    else:
        print('IBM Storage Scale RAID vdisk and file system summary:')
        print(34*'-')
        print('Total number of drives                {:>26d}'.
              format(numNodes * pdisksPerNode))
        print('Spare capacity in number of drives:   {:>26d}'.
              format(int(spares)))
        print('Total raw capacity (GiB):           {:>28.0f}'.
              format(total_pdisk_capacity))
        print('Declustered Array size (GiB):       {:>28.0f}'.
              format(da_capacity))
        print('Vdisk raw capacity  (GiB):          {:>28.0f}'.
              format(fromb(vdiskRawSize, 'GiB')))
        print('Vdisk user data capacity (GiB):     {:>28.0f}'.
              format(fromb(vdiskDataSize, 'GiB')))
        print('Maximum file system size (set-size = {:3d}%), '
              '(GiB):  {:>12.0f}'.format(setSize, max_fs_capacity))
        print('Maximum file system size (set-size = {:3d}%), '
              '(TB):   {:>12.2f}'.format(setSize, max_fs_capacity_tb))
        print('  [{0:.0f} GiB per vdisk,  2 vdisks per node, {1:} nodes]'.
              format(fromb(vdiskDataSize, 'GiB'), numNodes))
        print('')
        print('Storage Efficiency:')
        print(20*'-')
        print('File system to total raw capacity:  {:>28.2%}'.
              format(max_fs_capacity / total_pdisk_capacity))
        print('File system to DA raw capacity:     {:>28.2%}'.
              format(max_fs_capacity / float(da_capacity)))
        print('{0} erasure code efficiency:       {1:>28.2%}'.
              format(code,
                     float(dataStripsPerTrack) /
                     float(dataStripsPerTrack + parityStripsPerTrack)))
        print('')
        print('Please be ready for 1% variations on all the calculations')
        print('')
