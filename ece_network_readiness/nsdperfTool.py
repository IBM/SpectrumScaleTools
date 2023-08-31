#!/usr/bin/python
import os
import sys
import time
import getopt
import json
import math
import re
import threading
import subprocess

try:
    raw_input      # Python 2
    PYTHON3 = False
except NameError:  # Python 3
    raw_input = input
    PYTHON3 = True

# Global variables with default value
nsdperfPath = "/tmp/nsdperf"
toolPath = os.path.split(os.path.realpath(__file__))[0]
sshOption = "-o StrictHostKeyChecking=no -o LogLevel=error"
ssh = "ssh %s" % (sshOption)
scp = "scp %s" % (sshOption)
LOG_LOCK = threading.Lock()
timerWindow = 1200

# Regular expressions for IP
IPPATT = re.compile(r'inet\s+(?P<ip>\d+[\.]\d+[\.]\d+[\.]\d+)')

# Subroutines


def processArgs():
    if (not conf["server"] or not conf["client"]):
        halt("Error: you have to provide both --client and --server")
    dupNodes = [i for i in conf["server"] if i in conf["client"]]
    if (dupNodes):
        halt("Error: %s cannot be server and client at the same time, there "
             "shouldn't be duplicated nodes in servers and clients" % dupNodes)
    allowedTests = ["write", "read", "nwrite", "swrite", "sread", "rw"]
    for test in conf["test"]:
        if (test not in allowedTests):
            halt("Error: unknown test <%s>, please choose from <%s>"
                 % (test, allowedTests))
    if (not conf["test"]):
        conf["test"] = ["read", "nwrite"]


def createExecutable(node):
    rc = runcmd("%s %s \"test -d %s\"" % (ssh, node, nsdperfPath))[0]
    if (rc):
        chkcmd("%s %s \"mkdir -p %s\"" % (ssh, node, nsdperfPath))
    else:
        rc = runcmd("%s %s \"test -x %s_%s\"" %
                    (ssh, node, nsdperfexe, node))[0]
    cmd = ""
    if (rc or conf["rebuild"]):
        if (conf["rebuild"]):
            log("Force rebuild nsdperfexe on node %s as -r is specified" %
                (node))
        chkcmd("%s %s/nsdperf.C %s/makefile %s:%s/"
               % (scp, toolPath, toolPath, node, nsdperfPath))
        uname = chkcmd("%s %s \"uname -a\"" % (ssh, node))
        if (re.search("linux", uname, re.I)):
            verbsh = runcmd(
                "%s %s \"test -e /usr/include/infiniband/verbs.h\"" %
                (ssh, node))[0]
            rdmacmh = runcmd("%s %s \"test -e /usr/include/rdma/rdma_cma.h\"" %
                             (ssh, node))[0]
            if (verbsh or rdmacmh):
                log("INFO: verbs.h or rdma_cma.h could not be found. "
                    "nsdperf could not support RDMA on node %s." % (node))
                log("Excluding RDMA in compilation.")
                cmd = "cd %s; g++ -O2 -o nsdperfexe_%s -lpthread -lrt " \
                    "nsdperf.C" % (nsdperfPath, node)
            else:
                cmd = "cd %s; g++ -O2 -DRDMA -o nsdperfexe_%s -lpthread " \
                    "-lrt -libverbs -lrdmacm nsdperf.C" % (nsdperfPath, node)
        # elif (re.search("AIX", uname, re.I)):
        # TODO: support AIX?
        else:
            halt("Error: cannot compile %s/nsdperf.C on node $node, "
                 "OS is not supported." % (nsdperfPath))
        log("INFO: building nsdperfexe on node %s" % (node))
        chkcmd("%s %s \"%s\"" % (ssh, node, cmd))
    else:
        log("INFO: skip building nsdperfexe on node %s as %s_%s already "
            "exists. Use -r if you want to force rebuild." %
            (node, nsdperfexe, node))


def runTest(server, client):
    log("---------- Running nsdperf test with server %s client %s ----------"
        % (server, client))
    cliOptions = makeCmds(server, client)
    allNodes = []
    allNodes.extend(server)
    allNodes.extend(client)
    threads = []
    for node in allNodes:
        thr = threading.Thread(target=startServerThr, args=(node, cliOptions))
        thr.start()
        threads.append(thr)
    for thr in threads:
        thr.join()

    log("Get retransmit and packet loss data before test")
    netDataBefore = getNetData(client)
    if (conf["rdmaPorts"]):
        if (conf["rdmaPorts"][localNode]):
            localOpts = cliOptions + "-r %s " % (conf["rdmaPorts"][localNode])
    else:
        localOpts = cliOptions
    output = chkcmdLiveOutput(
        "%s_%s -i %s %s" % (nsdperfexe, localNode, nsdperfCmdFile, localOpts))
    log("Get retransmit and packet loss data after test")
    netDataAfter = getNetData(client)
    netData = {}
    for node in netDataBefore.keys():
        netData[node] = {}
        for key in netDataBefore[node].keys():
            netData[node][key] = int(netDataAfter[node][key]) - \
                int(netDataBefore[node][key])

    parseOutput(server, client, output, netData)


def makeCmds(server, client):
    cmdsInFile = ""
    cliOptions = ""
    joinStr = " "
    servers = joinStr.join(server)
    clients = joinStr.join(client)
    # File based options to nsdperf
    cmdsInFile = "server %s\nclient %s\n" % (servers, clients)
    if (conf["debugLevel"]):
        cmdsInFile = cmdsInFile + "debug %s\n" % (conf["debugLevel"])
        cliOptions = cliOptions + "-d "
    if (conf["ttime"]):
        cmdsInFile = cmdsInFile + "ttime %s\n" % (conf["ttime"])
    if (conf["testerThr"]):
        cmdsInFile = cmdsInFile + "threads %s\n" % (conf["testerThr"])
    if (conf["parallel"]):
        cmdsInFile = cmdsInFile + "parallel %s\n" % (conf["parallel"])
    if (conf["buffsize"]):
        cmdsInFile = cmdsInFile + "buffsize %s\n" % (conf["buffsize"])
    if (conf["socksize"]):
        cmdsInFile = cmdsInFile + "socksize %s\n" % (conf["socksize"])
    if (conf["rdmaPorts"] or conf["roce"]):
        cmdsInFile = cmdsInFile + "rdma on\n"
    if (conf["roce"]):
        cmdsInFile = cmdsInFile + "usecm on\n"  # Use Connection Manager for RoCE (not required for RDMA)
    for test in conf["test"]:
        cmdsInFile = cmdsInFile + "test %s\n" % (test)
    cmdsInFile = cmdsInFile + "killall\nquit"
    cmdFile = open(nsdperfCmdFile, 'w')
    cmdFile.write(cmdsInFile)
    cmdFile.close()
    # Parameters based to nsdperf (except debugLevel)
    if (conf["receiverThr"]):
        cliOptions = cliOptions + "-t %s " % (conf["receiverThr"])
    if (conf["workerThr"]):
        cliOptions = cliOptions + "-w %s " % (conf["workerThr"])

    return cliOptions


def startServerThr(node, cliOptions):
    killer(node, "nsdperfexe")
    # Give some time to die
    time.sleep(5)
    if (conf["rdmaPorts"]):
        nodeOpts = cliOptions + "-r %s " % (conf["rdmaPorts"][node])
    else:
        nodeOpts = cliOptions
    chkcmd("%s %s \"%s_%s -s %s > %s/server_thread_log 2>&1 &\""
           % (ssh, node, nsdperfexe, node, nodeOpts, nsdperfPath))
    # Give some time to start
    time.sleep(5)


def parseOutput(server, client, output, netData):
    resultFile = open(nsdperfResultFile, 'a')
    pattern = r"(\d+)-(\d+) (\w+) ([\d\.]+) MB/sec \(([\d\.]+) msg/sec\), " \
        r"cli (\d+\%) srv (\d+\%), time (\d+), buff (\d+)(.*)(\s*?(\S+ " \
        r"network delay times[\S\s]*?msec  nevents\s*(\s*\d+ +\d+\s*)*\s+)+)"
    resultSize = 0
    for match in (re.finditer(pattern, output)):
        result = {"server(s)": server, "client(s)": client}
        result["nServer"] = match.group(1)
        result["nClient"] = match.group(2)
        result["test"] = match.group(3)
        result["throughput(MB/sec)"] = match.group(4)
        result["throughput(msg/sec)"] = match.group(5)
        result["cli%"] = match.group(6)
        result["srv%"] = match.group(7)
        result["testTime"] = match.group(8)
        result["buffsize"] = match.group(9)

        sockThInfo = match.group(10)
        sock = re.search(r"sock (\d+)", sockThInfo)
        if (sock):
            result["socksize"] = sock.group(1)
        th = re.search(r"th (\d+)", sockThInfo)
        if (th):
            result["nTesterThread"] = th.group(1)

        result["networkDelay"] = []
        delay = {}
        allDelayInfo = match.group(11)
        oneDelayPattern = r"\S+ network delay times[\S\s]*?msec  nevents" \
            r"\s*(\s*\d+ +\d+\s*)*"
        for oneDelay in (re.finditer(oneDelayPattern, allDelayInfo)):
            detailedDelayPattern = r"(\S+) network delay times \(average " \
                r"([\d\.]+) msec, median ([\d\.]+) msec, std deviation " \
                r"([\d\.]+) msec\)\s+msec  nevents\s*((\s*\d+ +\d+\s*)*)"
            detailedDelay = re.search(detailedDelayPattern, oneDelay.group())
            if (detailedDelay):
                delay = {}
                delay["client"] = detailedDelay.group(1)
                delay["average"] = detailedDelay.group(2)
                delay["median"] = detailedDelay.group(3)
                delay["standardDeviation"] = detailedDelay.group(4)
                delay["histogram"] = {}
                allEvents = detailedDelay.group(5)
                eventPattern = r"(\d+) +(\d+)"
                for event in (re.finditer(eventPattern, allEvents)):
                    delay["histogram"][event.group(1)] = event.group(2)
                result["networkDelay"].append(delay)
            else:
                halt("Error, cannot match for network delay info")

        result["netData"] = netData
        outputJson = json.dumps(result)
        resultSize += sys.getsizeof(outputJson)
        resultFile.write(outputJson)
    resultFile.close()
    # Detect nsdperf test errors
    if (not resultSize):
        halt("Error, nsdperf test seems failed, please check command output")


def getLocalNode(allNodes):
    localNode = None
    rc, ipaddr_output, ec = runcmd("ip addr show")
    if (rc == 0):
        # create a list of allip addresses for local node
        iplist = IPPATT.findall(ipaddr_output)

        # check for match with one of input ip addresses
        for node in allNodes:
            if node in iplist:
                localNode = node
                break
    if localNode is None:
        halt("Error: cannot decide local node")
    return localNode


def getNodeDev(allNodes):
    # TODO: add support for hostname?
    netDev_raw = {}
    netDev = {}
    for node in allNodes:
        ipInfo = chkcmd("%s %s ip -f inet addr show" % (ssh, node))
        ipPattern = r"[\S\s]*\d+: (\S+): [\S\s]*?inet %s" % (node)
        try:
            netDev_raw[node] = re.search(ipPattern, ipInfo).group(1)
            netDev[node] = netDev_raw[node].split('@')[0]
            log("%s " % (netDev[node]))
            log("netDev: %s -> %s" % (node, netDev[node]))
        except Exception:
            halt("Error, cannot match for network device of node %s in "
                 "\"ip addr show\" output" % (node))
    return netDev


def getNetData(allNodes):
    netData = {}
    for node in allNodes:
        # TODO
        netData[node] = {}
        retransInfo = chkcmd(
            "%s %s nstat -az TcpRetransSegs" % (ssh, node))
        try:
            netData[node]["retransmit"] = re.search(
                r"TcpRetransSegs *(\d+)", retransInfo).group(1)
        except Exception:
            halt("Error, cannot match for retransmit data in "
                 "\"nstat -az TcpRetransSegs\" output on node %s" % (node))
        ipLinkInfo = chkcmd(
            "%s %s \"ip -s link show %s\"" % (ssh, node, netDev[node]))
        '''
        ip -s link output on until RHEL8.4:
            RX: bytes  packets  errors  dropped overrun mcast
            1664147533 23551653 0       15471   0       4118532
            TX: bytes  packets  errors  dropped carrier collsns
            7668665    75270    0       0       0       0
        ip -s link output from RHEL8.5:
            RX: bytes  packets  errors  dropped missed  mcast
            23489868   333950   0       0       0       0
            TX: bytes  packets  errors  dropped carrier collsns
            0          0        0       0       0       0
        '''
        ipLinkFormat = r"RX:\s+bytes\s+packets\s+(errors)\s+(dropped)\s+(overrun|missed)\s+(mcast)" \
            r"\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+TX:\s+bytes\s+" \
            r"packets\s+(errors)\s+(dropped)\s+(carrier)\s+(collsns)\s+\d+\s+\d+\s+(\d+)" \
            r"\s+(\d+)\s+(\d+)\s+(\d+)"

        ipLink = re.search(ipLinkFormat, ipLinkInfo)
        if (not ipLink):
            halt("Error, cannot match for network related data in "
                 "\"ip -s link\" output on node %s" % (node))
        #rxerrors
        netData[node]["rx"+ipLink.group(1)] = ipLink.group(5)
        #rxdropped
        netData[node]["rx"+ipLink.group(2)] = ipLink.group(6)
        #rxoverrun or rxmissed
        netData[node]["rx"+ipLink.group(3)] = ipLink.group(7)
        #rxmcast
        netData[node]["rx"+ipLink.group(4)] = ipLink.group(8)
        #txerrors
        netData[node]["tx"+ipLink.group(9)] = ipLink.group(13)
        #txdropped
        netData[node]["tx"+ipLink.group(10)] = ipLink.group(14)
        #txcarrier
        netData[node]["tx"+ipLink.group(11)] = ipLink.group(15)
        #txcollsns
        netData[node]["tx"+ipLink.group(12)] = ipLink.group(16)

    return netData


def shortUsage():
    print("Usage: %s -s|--server server1,server2,... "
          "-c|--client client1,client2,..." % (os.path.realpath(__file__)))
    print("          [-t|--test test1,test2,...] "
          "[-l|--testTime testTimeInSec]")
    print("          [-b|--buffsize buffsizeInByte] "
          "[-k|--socksize sockSizeInByte]")
    print("          [-R|--receiverThr nReceiverThread] "
          "[-W|--workerThr nWorkerThread] [-T|--testerThr nTesterThread]")
    print("          [-r|--rebuild] [-d|--directory dir] [-h|--help]")
    print("          [-x|--roce]")
    print("          [-p|--rdmaPorts]")


def longUsage():
    print("Usage: %s -s|--server server1,server2,... "
          "-c|--client client1,client2,..." % (os.path.realpath(__file__)))
    print("          [-t|--test test1,test2,...] "
          "[-l|--testTime testTimeInSec]")
    print("          [-b|--buffsize buffsizeInByte] "
          "[-k|--socksize sockSizeInByte]")
    print("          [-R|--receiverThr nReceiverThread] "
          "[-W|--workerThr nWorkerThread] [-T|--testerThr nTesterThread]")
    print("          [-r|--rebuild] [-d|--directory dir] [-h|--help]")
    print("          [--RDMA]")
    print("")
    print("This tool is a wrapper over nsdperf.C which helps to "
          "automatically build and execute nsdperf tests with given "
          "configurations.")
    print("All needed files and also test results in json format will be "
          "put under %s." % (nsdperfPath))
    print("")
    print("Node settings:")
    print("-s|--server server1,server2,...: server node list "
          "saparated by comma")
    print("-c|--client client1,client2,...: client node list "
          "saparated by comma")
    print("")
    print("Test settings:")
    print("-t|--test test1,test2,...: tests saparated by comma")
    print("-l|--testTime testTimeInSec: test time duration in seconds")
    print("Accepted tests: write|read|nwrite|swrite|sread|rw, default is "
          "\"read,nwrite\"")
    print("")
    print("Buffer settings:")
    print("-b|--buffsize buffsizeInByte: test buffer size in bytes")
    print("-k|--socksize sockSizeInByte: socket buffer size in bytes")
    print("")
    print("Thread settings:")
    print("-R|--receiverThr nReceiverThread: receiver thread number")
    print("-W|--workerThr nWorkerThread: worker thread number")
    print("-T|--testerThr nTesterThread: tester thread number")
    print("-P|--parallel nParallel socket connections")
    print("")
    print("Others:")
    print("-r|--rebuild: force rebuild the nsdperf executable before tests")
    print("-d|--directory dir: absolute path of local directory on "
          "each node to save nsdperf executable and output files, "
          "default is \"/tmp/nsdperf\"")
    print("-p|--rdmaPorts '{\"node1\": \"port11,port12\", "
          "\"node2\": \"port21,port22\", ...}': "
          "set different RDMA ports for each node and enable RDMA tests. ")
    print("OR -p|--rdmaPorts port1,port2: "
          "set same RDMA ports for all nodes and enable RDMA tests.")
    print("-x|--roce: enable connection manager for RoCE")          
    print("-h|--help: print this help message")


def log(msg):
    LOG_LOCK.acquire()
    timeStamp = getTimeStamp()
    tid = threading.currentThread().name
    print("%s: %s: %s" % (timeStamp, tid, msg))
    LOG_LOCK.release()


def getTimeStamp():
    return time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())


def halt(msg):
    log('\033[91m' + msg + '\033[0m')
    sys.exit(1)


def chkcmdLiveOutput(cmd):
    cmd = cmd.rstrip()
    log("CMD: %s" % (cmd))
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []
    rc = p.poll()
    while True:
        line = p.stdout.readline()
        rc = p.poll()
        line = line.rstrip()
        if (rc != None and (line == '' or line == b'')):
            break
        if PYTHON3:
            strline = ''.join(chr(x) for x in line)
            log(line)
            lines.append(strline)
        else:
            log(line)
            lines.append(line)
    if (rc):
        halt("Error, command failed with rc = %s" % (rc))
    out = '\n'
    return out.join(lines)


def chkcmd(cmd):
    [rc, out, err] = runcmd(cmd)
    out = out.rstrip()
    err = err.rstrip()
    if (rc):
        halt("Error, command <%s> get rc <%s> output <%s> error <%s>"
             % (cmd, rc, out, err))
    return out


def runcmd(cmd):
    cmd.rstrip()
    log("CMD: %s" % (cmd))
    if (re.search("2>&1", str(cmd))):
        cmd = cmd + " 2>&1"
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if PYTHON3:
        try:
            [out, err] = p.communicate(timeout = int(conf["ttime"]) + timerWindow)
        except subprocess.TimeoutExpired:
            killProcess(p)
            [out, err] = p.communicate()
        rc = p.wait()
        strout = ''.join(chr(x) for x in out)
        return [rc, strout, err]
    else:
        timer = threading.Timer(int(conf["ttime"]) + timerWindow, killProcess, [p])
        try:
            timer.start()
            [out, err] = p.communicate()
        finally:
            timer.cancel()
        rc = p.wait()
        return [rc, out, err]

def killProcess(process):
    log("Warning: test command not completing within (ttime + timerWindow), killing the subprocess")
    process.kill()

def killer(node, string):
    runcmd("%s %s killall -r .*%s.*" % (ssh, node, string))


# ========== main ==========

# Obtain command line options
conf = {'server': '', 'client': '', 'test': '', 'ttime': '', 'buffsize': '',
        'socksize': '', 'receiverThr': '', 'workerThr': '', 'testerThr': '',
        'rebuild': '', 'directory': '', 'rdmaPorts': '', 'debugLevel': '', 'roce':''}

try:
    opts, args = getopt.getopt(
                     sys.argv[1:], "hs:c:n:t:l:b:k:R:W:T:P:rd:p:vx",
                     ["help", "server=", "client=", "test=", "testTime=", "buffsize=",
                     "socksize=", "nReciverThr=", "nWorkerThr=", "nTesterThr=",
                     "nParallel=", "rebuild", "directory=", "rdmaPorts=", "debugLevel",
                     "roce"])
except getopt.GetoptError:
    shortUsage()
    sys.exit(1)

for op, value in opts:
    if op in ("-h", "--help"):
        longUsage()
        sys.exit(0)
    elif op in ("-s", "--server"):
        conf["server"] = value.split(",")
    elif op in ("-c", "--client"):
        conf["client"] = value.split(",")
    elif op in ("-t", "--test"):
        conf["test"] = value.split(",")
    elif op in ("-l", "--testTime"):
        conf["ttime"] = value
    elif op in ("-b", "--buffsize"):
        conf["buffsize"] = value
    elif op in ("-k", "--socksize"):
        conf["socksize"] = value
    elif op in ("-R", "--nReciverThr"):
        conf["receiverThr"] = value
    elif op in ("-W", "--nWorkerThr"):
        conf["workerThr"] = value
    elif op in ("-T", "--nTesterThr"):
        conf["testerThr"] = value
    elif op in ("-P", "--nParallel"):
        conf["parallel"] = value
    elif op in ("-r", "--rebuild"):
        conf["rebuild"] = True
    elif op in ("-d", "--directory"):
        nsdperfPath = value
    elif op in ("-p", "--rdmaPorts"):
        try:
            conf["rdmaPorts"] = json.loads(str(value))
        except Exception as e:
            log("I get non-json format --rdmaPorts input: <%s>" % value)
            log("Set it to be the RDMA ports for all nodes")
            rdmaPorts = {}
            for node in conf["server"]:
                rdmaPorts[node] = value
            for node in conf["client"]:
                rdmaPorts[node] = value
            conf["rdmaPorts"] = rdmaPorts
    elif op in ("-v", "--debugLevel"):
        conf["debugLevel"] = 5
    elif op in ("-x", "--roce"):
        conf["roce"] = True
    else:
        log("Error: Unknown option %s" % (op))
        shortUsage()
        sys.exit(1)

# process input arguments
processArgs()

# global variables that needs processing based on input args
nsdperfCmdFile = "%s/nsdperfCmd" % (nsdperfPath)
nsdperfResultFile = "%s/nsdperfResult.json" % (nsdperfPath)
nsdperfexe = "%s/nsdperfexe" % (nsdperfPath)
# allNodes
allNodes = []
allNodes.extend(conf["server"])
allNodes.extend(conf["client"])
# localNode
localNode = getLocalNode(allNodes)
# netDev
netDev = getNodeDev(allNodes)

# create nsdperfexe executable on all nodes if needed
threads = []
for node in allNodes:
    thr = threading.Thread(target=createExecutable, args=(node,))
    thr.start()
    threads.append(thr)
for thr in threads:
    thr.join()

# delete old result file before test
runcmd("rm -rf %s" % (nsdperfResultFile))
# run test
runTest(conf["server"], conf["client"])

log("========== All tests completed, congratulations! ==========")
log("========== Test result with json format is in file <%s> ==========" %
    (nsdperfResultFile))
