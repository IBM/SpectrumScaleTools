/******************************************************************************

  nsdperf - Test network performance, simulating GPFS NSD client / server

  See the README file for information about building and running
  this program.

  Changes in version 1.28:

    * Use a global table to hold pending replies.  The table is split into
      multiple buckets with a mutex for each one.  This should improve SMP
      performance, and also work more like GPFS.

    * For reply table, use a hash table with a free list per bucket instead
      of a map to avoid the need for shared memory allocation for entry
      elements.

    * On x86_64, use time stamp counter, if possible, to measure message
      transmission times.  This should have less overhead than making a
      system call to fetch the time of day.

    * Use global variable to stop tester threads so that they don't need to
      look at the time.

    * Use atomic ops to increment and decrement connection hold counter.
      Don't increment counter when creating a RcvMsg or ReplyEntry object
      since the connection won't go away while these exist.

    * Do zero-filling properly when printing timestamps.

    * Avoid aliasing complaints when compiling with -O3.

    * Show version in server startup log message.

  Changes in version 1.27:

    * Add support for more than one RDMA port when using Connection
      Manager.  Instead of using the IP address given on client or server
      command when making connections, scan all interfaces and use the
      ones whose IPv6 link-local addresses match the RDMA port interface
      identifier.  Only use interfaces that have a real (not link-local)
      IP address assigned.

    * Use only one RDMA context, completion channel, protection domain,
      and memory registration per device instead of one per port.

    * Don't bind to a specific port number when listening for Connection
      Manager requests.  Use whatever available port is assigned.  Remove
      the cmport command.

    * Increase the default number of message worker threads from 10 to 32.

    * Change "subnet number" to "fabric number" in RDMA port specification.

    * Add RDMA device name and port to some messages.

    * Improve the formatting of timestamps in debug output.

  Changes in version 1.26:

    * Allow RDMA connecting to work when multiple fabrics are present.
      For now, this is done by supplying a subnet number in the port
      definition.  RDMA connections will only be made between ports
      whose subnet numbers match.  Eventually this should be fixed so
      that the subnet identity is determined automatically.

    * Instead of using just one RDMA completion queue per device, use
      one for each target node.

  Changes in version 1.25:

    * Add "sinline" command to enable use of inline data in RDMA send.

  Changes in version 1.24:

    * Allow more than one RDMA port to be used.  The "-r" command line
      option can be used to select which ports to use.

    * New "maxrdma" command to specify maximum number of RDMA ports to use.

    * Send changes in debug level (from "debug" command) to remote hosts.

  Changes in version 1.23:

    * Add "usecm" command to enable use of Connection Manager to establish
      RDMA connections.

    * Add "cmport" command for specifying Connection Manager port number.

    * Show connection number along with destination host name.

  Changes in version 1.22:

    * Increase the maximum number of tester threads to 4096 and the
      maximum number of parallel connections to 8191.

    * Update help messages.

  Changes in version 1.20:

    * Command line option for specifying the number of receiver threads is
      now "-t" rather than "-r".

    * Add "-r" command line option for specifying the RDMA device and port.

    * On Linux systems, use epoll to wait for socket data.

  Changes in version 1.16:

    * Add a command to verify data message contents.

    * Add new RDMA options for sending control messages over the RDMA
      interface and sending data inline with control messages.

  Changes in version 1.14:

    * Add support for RDMA connections using verbs library.

    * Serialize writing of log message to stdout.

    * Include message rate in output statistics.

    * Require a space after "/" when used as a command delimiter.

  Changes in version 1.13:

    * Fixed ordering of in-use waiter queue that caused excessively
      long waits.

    * Use a separate pending reply table and message id for each
      connection to avoid contention for global locks.

    * Use nanosecond resolution for times.

******************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _LINUX_SOURCE_COMPAT

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <new>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#ifdef _AIX
#include <libperfstat.h>
#endif
#ifdef RDMA
#include <ifaddrs.h>
#include <infiniband/verbs.h>
#include <syscall.h>

/* Omni-Path 8K MTU Support */
#ifndef IBV_MTU_8192
#define IBV_MTU_8192 ((enum ibv_mtu)6)
#endif

#include <net/if.h>
#include <rdma/rdma_cma.h>

/* Maximum number of ibv_send_wr for RDMA read and write that can be
   chained and posted to WQ */
#define MAX_RDMA_SEND_WR 32
static int max_send_wr = MAX_RDMA_SEND_WR;
#endif

#ifdef AF_INET6
#define IPV6_SUPPORT
#endif

#ifdef __linux
#define USE_EPOLL
#endif

#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef __sparc
#define strerror_r(_e,_b,_s) strerror(_e)
#define INADDR_NONE INADDR_BROADCAST
#include <sys/filio.h>
#endif

using namespace std;


// Sized types
typedef unsigned char          UChar;
typedef short                  Int16;
typedef int                    Int32;
typedef long long              Int64;
typedef unsigned short         UInt16;
typedef unsigned int           UInt32;
typedef unsigned long long     UInt64;

// High-resolution time (nanosecond units)
typedef long long HTime;

// These definitions allow compatibility with the Windows Socket Library.
// They work in conjunction with a GPFS interface library.
#ifndef USE_WINSOCK
  // Socket type
  typedef int Sock;

  // Socket event description for the poll() function
  typedef struct pollfd PollSock;

  // The customary invalid socket value.
  static const Sock INVALID_SOCK = -1;
#endif

#define CACHE_LINE_SIZE 128

#if CACHE_LINE_SIZE == 0
#define __CACHE_LINE_ALIGNED__
#elif defined(__GNUC__)
#define __CACHE_LINE_ALIGNED__  __attribute__ ((aligned (CACHE_LINE_SIZE)))
#else
#define __CACHE_LINE_ALIGNED__
#endif

#define MIN_VERBS_SEND_SGE (1)
#define MAX_VERBS_SEND_SGE (128)
#define DEFAULT_VERBS_SEND_SGE (27)

#define DEF_SCATTER_BYTES (262144)

typedef struct GlobalVerbs_t
{
  int VerbsRdmaMaxSendBytes;
  int VerbsMaxSendSge;
} GlobalVerbs_t;

GlobalVerbs_t GlobalVerbs __CACHE_LINE_ALIGNED__ =
{
  DEF_SCATTER_BYTES,          /* VerbsRdmaMaxSendBytes */
  DEFAULT_VERBS_SEND_SGE,     /* VerbsMaxSendSge */
};

// Message ID type
typedef UInt32 MsgId;

// Program version
static const string version = "1.28";

// Default port to use
static const int NSDPERF_PORT = 6668;

// Default number of message worker threads
static const int MSG_WORKERS = 32;

// Default number of tester threads
static const unsigned int TESTER_THREADS = 4;

// Maximum number of tester threads
static const unsigned int MAX_TESTERS = 4096;

// Maximum size for data buffer
static const unsigned int DEF_BUFFSIZE =  4 * 1024 * 1024;
static const unsigned int MIN_BUFFSIZE =  4 * 1024;
static const unsigned int MAX_BUFFSIZE = 16 * 1024 * 1024;

// Maximum size for data part of a control message
static const unsigned int MAX_RPCSIZE = 64;

// Maximum TCP send/receive buffer size
static const int MAX_SOCKSIZE = 100 * 1024 * 1024;

// Maximum number of FDs to pass to poll
static const int MAX_POLLFD_NUM = 8192;

// Value for maxrdma that means unlimited
static const int MAXRDMA_UNLIMITED = INT_MAX;

// Maximum number of parallel connections
static const int MAX_PARALLEL = MAX_POLLFD_NUM - 1;

// Size of a message header
static const unsigned int MSG_HDRSIZE = 4 * sizeof(UInt32) + 6 * sizeof(HTime);

// Magic number for message headers
static const UInt32 MSG_MAGIC = 0x1F2E3D4CU;

// For scrambling data in test data buffers
static const UInt64 SCRAMBLE = 0x0305070b0d111317ULL;

// Maximum possible value for an HTime
static const long long MAX_HTIME = 0x7FFFFFFFFFFFFFFFLL;

// For ioctl arguments
static const int on = 1;

// Flag to use in sendmsg system call to prevent EPIPE errors.  Some
// systems don't have this.
#ifdef MSG_NOSIGNAL
static const int SENDMSG_FLAGS = MSG_NOSIGNAL;
#else
static const int SENDMSG_FLAGS = 0;
#endif


// Forward declarations
class MsgRecord;
class MsgWorker;
class PollWait;
struct RcvMsg;
class RdmaConn;
struct RdmaPort;
class RdmaReceiver;
class Receiver;
struct Target;
struct TestReq;
class Tester;
class Thread;


// Error macros
#define Warn(msg) do \
  { pthread_mutex_lock(&logMutex); \
    cerr << progname << ": Warning: " << msg << endl; \
    pthread_mutex_unlock(&logMutex); } while (false)
#define Warnm(msg) do \
  { pthread_mutex_lock(&logMutex); \
    cerr << progname << ": Warning: " << msg << ": "; perror(""); \
    pthread_mutex_unlock(&logMutex); } while (false)
#define Error(msg) do \
  { pthread_mutex_lock(&logMutex); cerr << progname << ": " << msg << endl; \
    exit(EXIT_FAILURE); } while (false)
#define Errorm(msg) do \
  { pthread_mutex_lock(&logMutex); cerr << progname << ": " << msg << ": "; \
    perror(""); exit(EXIT_FAILURE); } while (false)

// Console log output macros
#define Log(msg) do \
  { thLock(&logMutex); cout << msg << endl; thUnlock(&logMutex); } \
  while (false)
#define Logt(lev, msg) do \
  { if (debugLevel >= (lev)) \
    { thLock(&logMutex); \
      cout << httostr(getTime()) << " " << msg << endl; \
      thUnlock(&logMutex); } \
  } while (false)
#define Logm(msg) do \
  { int e = errno; thLock(&logMutex); \
    cout << msg << ": " << geterr(e) << endl; \
    thUnlock(&logMutex); } while (false)


// Error codes
enum Errno
{
  E_OK,
  E_INVAL,
  E_NOENT,
  E_WOULDBLOCK,
  E_CONNRESET,
  E_BADMSG,
  E_BROKEN,
  E_SENDFAILED,
  E_REPLY,
  E_CONNFAILED
};


// Address types for IpAddr
enum Atype
{
  AT_IPV4,
  AT_IPV6
};


// Structure for holding an IPv4 or IPv6 address
struct IpAddr
{
  Atype fam;
  UChar a[16];
  IpAddr() { setNone(); }
  bool operator<(const IpAddr &iaddr) const;
  bool operator!=(const IpAddr &iaddr) const;
  void setNone();
  void setAny();
  Errno parse(const string hostname);
  void loadSockaddr(const sockaddr *saddrP);
  string toString() const;
  sockaddr *toSockaddr(UInt16 port, sockaddr_storage *sockBuffP) const;
  socklen_t getSocklen() const;
  static int getSize() { return sizeof(UInt32) + sizeof(UChar[16]); /* a */ }
#ifdef IPV6_SUPPORT
  int getFamily() const { return (fam == AT_IPV6) ? AF_INET6 : AF_INET; }
#else
  int getFamily() const { return AF_INET; }
#endif
  bool isLinkLocal() const;
  bool isNone() const;
};


// Structure for holding an RDMA memory address (i.e. a character pointer)
// for passing between nodes.
struct RdmaAddr
{
  UInt64 addr;
  RdmaAddr() { addr = 0; }
  RdmaAddr(UInt64 a) : addr(a) {}
  RdmaAddr(char *p) : addr(reinterpret_cast<UInt64>(p)) {}
  operator char *() { return reinterpret_cast<char *>(addr); }
  operator UInt64() { return addr; }
};


// Structure to record time line of each message
struct TimeLine
{
  HTime rdStartStamp;
  HTime rdFinStamp;
  HTime msgSendStamp;     // Time stamp when message is sent on sender side
  HTime msgRecvStamp;     // Time stamp when message is received and recognized on receiver side
  HTime replySendStamp;     // Time stamp when message is sent on sender side
  HTime replyRecvStamp;     // Time stamp when message is received and recognized on receiver side

  TimeLine()
  {
    rdStartStamp = 0;
    rdFinStamp = 0;
    msgSendStamp = 0;
    msgRecvStamp = 0;
    replySendStamp = 0;
    replyRecvStamp = 0;
  }

  ~TimeLine() {}

  HTime getNetworkDelay()
  {
    return (rdFinStamp - rdStartStamp + replyRecvStamp - msgSendStamp - \
      (replySendStamp - msgRecvStamp));
  }
};


// Abstract base class for threads.  Derived class must supply the routine
// body.
class Thread
{
  pthread_t th;

protected:
  bool running;

public:
  Thread() : th(0), running(false) {}
  virtual ~Thread() {}
  void init();
  void startup();
  pthread_t getThread() const { return th; }
  virtual int threadBody() = 0;
};


// Thread states
enum thState { tsRun, tsDie, tsDead };


// Data buffer that allows putting and getting items for sending in messages
class DataBuff
{
  char *buffP;                  // The data buffer
  unsigned int alloc;           // Actual allocated length
  unsigned int bufflen;         // Length currently assigned to buffer
  unsigned int buffpos;         // Position for put/get
  char *auxBuffP;               // Extra buffer used for inline RDMA
  unsigned int auxlen;          // Length of extra buffer

public:
  DataBuff()
    { buffP = auxBuffP = NULL; alloc = bufflen = buffpos = auxlen = 0; }
  DataBuff(unsigned int len)           { alloc = 0; newBuff(len); }
  DataBuff(char *dP, unsigned int len) { alloc = 0; initBuff(dP, len); }
  ~DataBuff() { if (alloc > 0) delete [] buffP; }
  void newBuff(unsigned int len);
  void initBuff(char *dataP, unsigned int datalen);
  void fillBuff(UInt64 seed);
  bool verifyBuff(UInt64 seed);
  void resetBuff() { buffpos = 0; }
  char *getBuffP() { return buffP; }
  unsigned int getBufflen() const { return bufflen; }
  void setAux(char *dataP, unsigned int datalen)
    { auxBuffP = dataP; auxlen = datalen; }
  char *getAuxBuffP() { return auxBuffP; }
  unsigned int getAuxlen() { return auxlen; }
  void putUInt16(UInt16 i);
  void putInt32(Int32 i);
  void putUInt32(UInt32 i);
  void putUInt64(UInt64 i);
  void putRdmaAddr(RdmaAddr a);
  void putHTime(HTime t);
  void putIpAddr(IpAddr iaddr);
  void putString(string s);
  void putTimeLine(TimeLine *timeline);
  UInt16 getUInt16();
  Int32 getInt32();
  UInt32 getUInt32();
  UInt64 getUInt64();
  RdmaAddr getRdmaAddr();
  HTime getHTime();
  IpAddr getIpAddr();
  string getString();
  TimeLine* getTimeLine();
};


// Gather histogram of response times
class Histogram
{
  map<HTime, UInt32> buckets;
  int nEvents;
  HTime totalTime;

public:
  Histogram() { nEvents = 0; totalTime = 0; }
  void addEntry(HTime t);
  void addHist(const Histogram *hP);
  void printHist(ostream &os) const;
  void putBuff(DataBuff *dbP) const;
  void getBuff(DataBuff *dbP);
  int getNevents() const { return nEvents; }
  unsigned int calcLen() const
    { return sizeof(UInt64) + 2 * sizeof(UInt32) +
        buckets.size() * (sizeof(UInt64) + sizeof(UInt32)); }
  double average() const;
  double median() const;
  double standardDeviation() const;
  double minTime() const;
  double maxTime() const;
  UInt32 maxBucket() const;
};


// Compare two histogram bucket entries by bucket value
struct BucketCmp
{
  bool operator()(pair<HTime, UInt32> p1, pair<HTime, UInt32> p2) const
  { return p1.second < p2.second; }
};


// Receive states of a connection
enum RState
{
  rcv_idle,
  rcv_header,
  rcv_data
};


// Message type codes
enum MType
{
  mtUnknown,            // Unknown
  mtReply,              // Reply message
  mtReplyErr,           // Error reply message
  mtVersion,            // Query version
  mtWrite,              // Accept buffer of test data
  mtRead,               // Send back a buffer of test data
  mtNwrite,             // NSD style write: target asks for test data
  mtGetdata,            // Fetch data in response to NSD write request
  mtKill,               // Tell destination node to exit
  mtConnect,            // Connect to specified servers
  mtReset,              // Close any existing server connections
  mtRdmaDone,           // Close RDMA connections to servers at end of test
  mtRdmaConn,           // Set up RDMA connection
  mtRdmaGetBuffs,       // Return addresses of RDMA buffers to use for test
  mtRdmaDisconnCM,      // Tell connection manager to disconnect
  mtRdmaDisconn,        // Tear down RDMA connection
  mtRdmaCleanup,        // Delete RDMA connection object
  mtRdmaWrite,          // Accept data that has been written through RDMA
  mtParms,              // Set test parameters
  mtAlloc,              // Allocate memory buffers
  mtFree,               // Free buffers allocated by mtAlloc
  mtTest,               // Run performance test to all servers
  mtStatus,             // Return node status
  mtStatOn,             // Turn on test statistics gathering
  mtStatOff,            // Turn off test statistics gathering
  mtIdlePct,            // Get idle CPU percentage from last test
  mtLast                // Highest message type number
};


// An entry in the queue of waiters for exclusive use of a socket for sending
struct InuseWaiter
{
  // Wake this when the socket is available
  pthread_cond_t iwCond;

  // The following fields are used to determine priority between waiters
  MType mt;             // Original msgType (not mtReply or mtReplyErr)
  MsgId msgId;          // Message identifier (earlier messages are lower)
  unsigned int datalen; // Length of the message

  InuseWaiter();        // Default constructor - not defined
  InuseWaiter(MType tmt, MsgId tmsgId, unsigned int tdatalen);
};


// Function object to compare two InuseWaiter entries to determine which
// has higher priority
struct InuseCmp
{ bool operator()(const InuseWaiter *w1P, const InuseWaiter *w2P) const; };


// An RDMA port specification (device name, port number, fabric number),
// from RDMAPORTS command option
struct RdmaPortName
{
  string devName;
  int rport;            // Negative value matches any port number
  int fabnum;           // Not included in compares
  RdmaPortName() : rport(-1), fabnum(0) {}
  RdmaPortName(string dev, int p, int f) : devName(dev), rport(p), fabnum(f) {}

  // Comparison operator for inserting port names into sets.  The fabric
  // number isn't used since a port name must be on only one fabric.
  bool operator<(const RdmaPortName &p) const
  {
    if (devName != p.devName)
      return devName < p.devName;
    if (rport != p.rport && rport >= 0 && p.rport >= 0)
      return rport < p.rport;
    return false;
  }
};


// Information about an RDMA port.  These objects are exchanged among nodes
// so that they know where to connect.
struct RdmaPortInfo
{
  string piName;                // Device name
  int piPort;                   // Port number within device
  int piFabnum;                 // Fabric number
  UInt64 piPortIf;              // Interface ID
  IpAddr piAddr;                // IP address (CM only)
  UInt16 piCmPort;              // Port number (CM only)

  RdmaPortInfo() : piPort(0), piFabnum(0), piPortIf(0), piCmPort(0) {}
  RdmaPortInfo(const RdmaPort *rportP);

  unsigned int calcPortInfoLen() const;
  void putBuff(DataBuff *dbP) const;
  void getBuff(DataBuff *dbP);
  string toString() const;

  // Comparison operator for inserting port names into sets.  The fabric
  // number isn't used since a port name must be on only one fabric.
  bool operator<(const RdmaPortInfo &p) const
  {
    if (piName != p.piName)
      return piName < p.piName;
    if (piPort != p.piPort && piPort >= 0 && p.piPort >= 0)
      return piPort < p.piPort;
    return false;
  }

  // For sorting ports by fabric number, name, and port number
  static bool comp(const RdmaPortInfo *p1P, const RdmaPortInfo *p2P)
  {
    if (p1P->piFabnum != p2P->piFabnum)
      return p1P->piFabnum < p2P->piFabnum;
    if (p1P->piName != p2P->piName)
      return p1P->piName < p2P->piName;
    return p1P->piPort < p2P->piPort;
  }
};


// TCP connection
class TcpConn
{
  pthread_mutex_t connMutex;
  pthread_cond_t connCond;
  priority_queue<InuseWaiter *, vector<InuseWaiter *>, InuseCmp> waiters;

  int refCount;
  Sock tcSock;
  IpAddr dest;
  bool inuse;           // Serializer for senders
  bool broken;          // True if socket was shut down due to error
  int cnum;             // TCP connection number
  Histogram connHist;   // Histogram of response times from last test
  Histogram connLat;	// Histogram of latency times from last test
  static int nextCnum;  // Next connection number (protected by globalMutex)
#ifdef RDMA
  int lastConnNdx;              // Hint about which connection was used last
  int nRconns;                  // Count of entries in rconnTab
  vector<RdmaConn *>rconnTab;   // RDMA connections
  list<RdmaAddr>remoteBuffs;    // RDMA buffers on remote side for write tests
  list<char *>givenBuffs;       // RDMA buffers that we have given out
#endif

  // Receiver thread state
  RState recvState;
  char *recvP;          // Receive pointer
  int recvlen;          // Length of data received so far
  int recvmax;          // Size of receive buffer
  RcvMsg *recvMsgP;     // Message will be received here

public:
  TcpConn();            // Default constructor - not defined
  TcpConn(Sock tsock, IpAddr tdest);
  ~TcpConn();
  string destName() const;
  Histogram *getHistP() { return &connHist; }
  Histogram *getLatP() { return &connLat; }
  bool isBroken() const { return broken; }
  int getCnum() const   { return cnum; }
  Sock getSock() const  { return tcSock; }
  IpAddr getDest() const { return dest; }
  MsgId assignMsgId();
  void holdConn();
  void releaseConn();
  void connShutdown();
  void receiveDone();
  Errno receiverEvent();
  void gotMsg(RcvMsg *rmsgP);
  void getSourceAddr(MsgId msgId, char **srcAddrPP, unsigned int *srcLenP);
  Errno recvMessage();
  Errno sendMessage(MType mt, DataBuff *dbP, MsgRecord *mrP,
                    PollWait *pwaitP = NULL, TimeLine *timeLine = new TimeLine());
  Errno sendit(MType mt, MType origmt, MsgId msgId, DataBuff *mdbP,
               MsgRecord *mrP, PollWait *pwaitP, TimeLine *timeLine = new TimeLine());
#ifdef RDMA
  int getNRconns() const { return nRconns; }
  string rdmaClientConnect(const set<RdmaPortInfo> *remotePortsP);
  void rdmaServerConnect(RcvMsg *rmsgP);
  void rdmaSendCMDiscReq();
  void rdmaRecvCMDiscReq(RcvMsg *rmsgP);
  void rdmaDisconnect();
  void rdmaCleanup();
  void rdmaWrite(DataBuff *testBuffP, RdmaAddr raddr, UInt32 rlen,
                 PollWait *pwaitP);
  void rdmaRead(RdmaAddr raddr, UInt32 rlen, char *dataP, PollWait *pwaitP);
  void rdmaSend(DataBuff *dbP, PollWait *pwaitP);
  void rdmaGiven(char *buffP) { givenBuffs.push_back(buffP); }
  RdmaAddr getRemoteBuff();
  void freeRemoteBuff(RdmaAddr rBuff);
  RdmaConn *chooseRconnP();
#endif
};


#ifdef RDMA
// Unique key to locate TcpConn object for incoming RDMA connection
// manager events.
struct ConnKey
{
  int cnum;                     // TCP connection number
  IpAddr iaddr;                 // IP address
  IpAddr saddr;
  ConnKey() : cnum(0) {}
  ConnKey(int c, const IpAddr &ia, const IpAddr &sa) : cnum(c), iaddr(ia), saddr(sa) {}
  bool operator<(const ConnKey &k) const
    {
      if (cnum != k.cnum)
	return cnum < k.cnum;
      if (iaddr != k.iaddr)
	return iaddr < k.iaddr;
      return saddr < k.saddr;
    }
};

static const char *ibv_wc_status_str_nsdperf(enum ibv_wc_status status);
static const char *ibv_wr_opcode_str(enum ibv_wr_opcode opcode);

// RDMA connection
class RdmaConn
{
  pthread_mutex_t cmMutex;      // For waiting on CM events
  pthread_cond_t cmCond;
  rdma_cm_event *cmEventP;      // To pass event between handler and waiter
  int cmWaiting;                // Count of threads waiting for a CM event
  bool cmBroken;                // True if forcibly disconnecting
  rdma_cm_id *cmId;             // Communications identifier for CM
  ibv_qp *qp;                   // Queue pair
  unsigned int maxInline;       // Maximum bytes that can be sent inline
  UInt32 rkey;                  // Remote memory key
  UInt32 llid, rlid;            // Local and remote lid
  Int32 remoteNdx;              // Index into rconnTab on remote node
  list<PollWait *>pwList;       // Receive requests
  TcpConn *connP;               // TCP connection that owns this object
  int rconnNdx;                 // Index into rconnTab for this connection
  RdmaPort *rdmaPortP;          // The RDMA port
  RdmaPortInfo remotePinfo;     // Information about the port at the other end
  pthread_mutex_t bytesMutex;   // Mutex for bytesPending
  UInt64 bytesPending;          // Bytes in flight (protected by bytesMutex)

public:
  RdmaConn(TcpConn *tconnP, int ndx);
  ~RdmaConn();
  Int32 rdGetRemoteNdx() const { return remoteNdx; }
  rdma_cm_id *rdWaitForCMConn(const ConnKey *ckeyP,
                              int *responder_resourcesP,
                              int *initiator_depthP);
  void rdCMListen();
  string rdConnInfo() const;
  string rdPrepClient(TcpConn *connP, RdmaPort *rportP,
                      const RdmaPortInfo *destPortInfoP);
  string rdPrepServer(RcvMsg *rmsgP, TcpConn *connP, DataBuff *dbP);
  void rdPrepPost(TcpConn *connP);
  void rdPostRecv(PollWait *pwaitP);
  void rdConnect(UInt32 qpnum, UInt32 maxQpRd, const char *whoP);
  void rdDisconnectCM(string name);
  void rdDisconnect();
  void rdCleanup();
  void rdWrite(DataBuff *testBuffP, RdmaAddr raddr, UInt32 rlen, PollWait *pwaitP);
  void rdRead(RdmaAddr raddr, UInt32 rlen, char *dataP, PollWait *pwaitP);
  void rdSend(DataBuff *dbP, PollWait *pwaitP);
  void rdRecv(PollWait *pwaitP, unsigned int len);
  void rdHandleCMEvent(rdma_cm_event *eventP);
  string rdCheckCMEvent(const string func, enum rdma_cm_event_type expectedEv,
                        enum rdma_cm_event_type errEv);
  void rdAddBytes(UInt64 nBytes);
  void rdSubBytes(UInt64 nBytes);
  UInt64 rdGetBytesPending() const { return bytesPending; };
};
#endif // RDMA


// Target node for test
struct Target
{
  string hostname;
  IpAddr iaddr;                 // IP address
  TcpConn *connP;               // TCP connection (null if not connected)
  set<RdmaPortInfo> remPinfo;   // RDMA ports on remote node
  bool isClient;                // True if this is a client node
  bool active;                  // For detecting inactive Targets
  bool didAlloc, didConnect;    // Used by test command to track progress

  Target();                     // Default constructor - not defined
  Target(const Target &m);      // Copy constructor - not defined
  Target(const string thostname, const IpAddr tiaddr) :
    hostname(thostname), iaddr(tiaddr), connP(NULL), isClient(false),
    active(true), didAlloc(false), didConnect(false) {}
  ~Target();
  string makeConnection();
  int calcConnectionCount() const;
  RcvMsg *sendm(MType mt, DataBuff *dbP = NULL, PollWait *pwaitP = NULL,
                char *srcAddrP = NULL, unsigned int srcLen = 0, TimeLine *timeline = new TimeLine());
  string name() const;
};


// For sorting Target objects for round-robin scheduling
struct SortedTarget
{
  int tindex;
  Target *targP;
  SortedTarget(int ndx, Target *tP) : tindex(ndx), targP(tP) {}
  static bool comp(const SortedTarget t1, const SortedTarget t2)
  {
    if (t1.tindex != t2.tindex) return t1.tindex < t2.tindex;
    return t1.targP->iaddr < t2.targP->iaddr;
  }
};


// Structure to hold received messages
struct RcvMsg
{
  TcpConn *connP;               // The connection that this message came from
  char hdr[MSG_HDRSIZE];        // Buffer for receiving message header
  DataBuff msgBuff;             // Buffer for message data
  MsgId msgId;                  // Message identifier
  MType msgType;                // Message type
  TimeLine *timeLine;            // Record time line for each message
  int rconnNdx;                 // Which RDMA connection the message came in on
  string errText;               // Error message, or empty if no error

  RcvMsg();                     // Default constructor - not defined
  RcvMsg(const RcvMsg &m);      // Copy constructor - not defined
  RcvMsg(TcpConn *tconnP)
  {
    connP = tconnP;
    memset(hdr, 0, MSG_HDRSIZE);
    msgId = 0;
    msgType = mtUnknown;
    rconnNdx = -1;
    timeLine = new TimeLine();
  }
  ~RcvMsg()                     {}
  char *msgBuffP()              { return msgBuff.getBuffP(); }
  unsigned int msgLen() const   { return msgBuff.getBufflen(); }
  void sendReply(DataBuff *dbP, string errText = "", PollWait *pwaitP = NULL);
  bool showError();
  bool startAdminReq();
  void endAdminReq();
  void dispatch(MsgWorker *mwP);

  // Message handlers
  void handleVersion();
  void handleKill();
  void handleWrite(MsgWorker *mwP);
  void handleRdmaWrite(MsgWorker *mwP);
  void handleRead(MsgWorker *mwP);
  void handleNwrite(MsgWorker *mwP);
  void handleGetdata(MsgWorker *mwP);
  void handleConnect();
  void handleReset();
  void handleRdmaDone();
  void handleRdmaConn();
  void handleRdmaGetBuffs();
  void handleRdmaDisconnCM();
  void handleRdmaDisconn();
  void handleRdmaCleanup();
  void handleParms();
  void handleAlloc();
  void handleFree();
  void handleTest();
  void handleStatus();
  void handleIdlePct();
};


// This object is used to wait for pending replies
class MsgRecord
{
  pthread_mutex_t waitMutex;
  pthread_cond_t waitCond;
  set<MsgId> waitTab;           // IDs of pending messages
  list<RcvMsg *> replies;       // Reply data

public:
  char *srcAddrP;               // Data buffer for GetData requests
  unsigned int srcLen;          // Length of the above buffer

  MsgRecord(char *tsrcAddrP = NULL, unsigned int tsrcLen = 0);
  ~MsgRecord();
  void addMsg(MsgId msgId);
  void waitForReplies();
  bool checkReplies();
  void gotReply(RcvMsg *rmsgP);
  RcvMsg *nextReply();
};


// An object for waiting on RDMA I/O requests
class PollWait
{
#ifdef RDMA
  pthread_mutex_t pwMutex;
  pthread_cond_t pwCond;
  bool complete;

public:
  char *srvBuffP;
  char *cliBuffP;
  UInt64 opId;
  UInt32 buffLen;
  ibv_wr_opcode opcode;
  enum ibv_wc_status status;
  int tid;
  char *mbufP;                  // Registered message buffer (optional)
  RdmaConn *rconnP;             // Connection that message came in on
                                //   (only used for receive requests)
  PollWait() { init(); }
  PollWait(RdmaConn *rP);
  ~PollWait();
  void init();
  ibv_wc_status wait();
  void wakeup(ibv_wc_status s);
  bool isComplete() const { return complete; }
#else
public:
  char *mbufP;
  PollWait() : mbufP(NULL) {}
#endif // RDMA
};


#ifdef RDMA
/* An RDMA device (host adapter) */
struct RdmaDevice
{
  ibv_context *ibContext;
  string rdmaDevName;
  ibv_device_attr ibAttr;
  ibv_comp_channel *ibCC;
  ibv_pd *ibPD;
  ibv_mr *ibMR;
  int cqSize;
  map<int, ibv_cq *> cqtab;
  thState rdmaRcvState;
  RdmaReceiver *rdmaRcvThreadP;

  RdmaDevice(ibv_context *ctx);
  void initDev();
  ibv_cq *createCQ(int cnum);
  void destroyCQ();
  void getQpAttributes(ibv_qp_init_attr *qpIAttrP, ibv_cq *cq) const;
};


// An RDMA port (something that can be plugged into a fabric).  An RDMA
// device can have several of these with different port numbers.
struct RdmaPort
{
  RdmaDevice *pdevP;
  UInt64 portIf;
  IpAddr portAddr;
  int rdmaPortnum, rdmaFabnum;

  RdmaPort(RdmaDevice *devP, UInt64 pif, IpAddr a, int port, int fabnum) :
    pdevP(devP), portIf(pif), portAddr(a),
    rdmaPortnum(port), rdmaFabnum(fabnum) {}
  string devString() const;

  // For sorting ports by fabric number, name, and port number
  static bool comp(const RdmaPort *d1P, const RdmaPort *d2P)
  {
    if (d1P->rdmaFabnum != d2P->rdmaFabnum)
      return d1P->rdmaFabnum < d2P->rdmaFabnum;
    if (d1P->pdevP->rdmaDevName != d2P->pdevP->rdmaDevName)
      return d1P->pdevP->rdmaDevName < d2P->pdevP->rdmaDevName;
    return d1P->rdmaPortnum < d2P->rdmaPortnum;
  }
};


// Information about a network interface
struct NetIface
{
  IpAddr addr;
  string ifName;
};
#endif


// This object is saved in the pending reply table to keep track of
// outstanding replies.  Each message has a unique MsgId which is used to
// find the ReplyEntry when the reply comes in.
struct ReplyEntry
{
  MsgId msgId;                  // Message ID for this entry
  MsgRecord *mrP;               // MsgRecord to wake up when reply comes in
  TcpConn *connP;               // Connection where the message was sent
  ReplyEntry *reNextP;          // Next in hash bucket or free list

  ReplyEntry();                 // Default constructor - not defined
  ReplyEntry(const ReplyEntry &m); // Copy constructor - not defined
  ReplyEntry(MsgId m, MsgRecord *tmrP, TcpConn *tconnP) :
    msgId(m), mrP(tmrP), connP(tconnP), reNextP(NULL) {}
  ~ReplyEntry() {}
};


// Test types
enum TType
{
  ttWrite,              // Round-robin write
  ttRead,               // Round-robin read
  ttNwrite,             // NSD-style write
  ttRW,                 // Simultaneous read and write
  ttSwrite,             // Single node write per tester
  ttSread,              // Single node read per tester
  ttLast
};


// An object to hold info about a node used by the tester thread
struct TNodeInfo
{
  Target *targP;        // Target node
  RdmaAddr tBuff;       // RDMA memory buffer on target for write tests
  TNodeInfo(Target *tP, RdmaAddr tb) : targP(tP), tBuff(tb) {}
};


// Tester thread work request
struct TestReq
{
  TType tt;
  list<TNodeInfo> testNodes;
  UInt64 totBytes;
  Histogram hist;
  Histogram lat;
  string errText;

  TestReq(TType ttt)
  {
    tt = ttt;
    totBytes = 0;
  }
};


// An entry in the newSockets list of the receiver thread
struct NewSock
{
  Sock sock;
  TcpConn *connP;
  NewSock(Sock tsock, TcpConn *tconnP) : sock(tsock), connP(tconnP) {}
};


// A receiver thread
class Receiver : public Thread
{
  pthread_mutex_t receiverMutex;        // Protects newSockets
  pthread_cond_t receiverCond;          // For additions to newSockets
  list<NewSock> newSockets;             // New sockets for receiver thread
  Sock rcvSocks[2];                     // Socket pair for waking up poll

public:
  Receiver();
  virtual ~Receiver();
  void addConn(Sock sock, TcpConn *connP);
  void wakeUp();
  void nudge();
  virtual int threadBody();
};


// Message worker thread
class MsgWorker : public Thread
{
public:
  char *rdBuffP;        // RDMA buffer to get nwrite data (server only)
  unsigned int rdLen;   // Length of the above buffer
  PollWait pwait;       // For waiting on RDMA requests
  DataBuff rtestBuff;   // Test data for read replies (server only)

  MsgWorker() : rdBuffP(NULL), rdLen(0) {}
  virtual ~MsgWorker();
  void getRdmaBuff();
  void freeRdmaBuff();
  virtual int threadBody();
};


// Tester thread
class Tester : public Thread
{
  TestReq *reqP;

public:
  Tester() : reqP(NULL) {}
  virtual ~Tester() {}
  virtual int threadBody();
  void doTest(TestReq *trP);
};


// Listen/accept thread
class ListenAccept : public Thread
{
  int currsize;                 // Socket buffer size currently in use
public:
  ListenAccept() : currsize(0) {}
  virtual ~ListenAccept() {}
  virtual int threadBody();
  void updateSocksize();
};


#ifdef RDMA
// RDMA receiver thread
class RdmaReceiver : public Thread
{
  RdmaDevice *rdmaRecDevP;
public:
  RdmaReceiver(RdmaDevice *rP) : rdmaRecDevP(rP) {}
  virtual ~RdmaReceiver() {}
  virtual int threadBody();
};


// RDMA async event handler thread
class RdmaAsync : public Thread
{
  Sock asyncSocks[2];           // Socket pair for waking up poll
public:
  RdmaAsync();
  virtual ~RdmaAsync();
  void wakeUp();
  virtual int threadBody();
};


// RDMA connection manager event handler thread
class RdmaCM : public Thread
{
public:
  RdmaCM() {}
  virtual ~RdmaCM() {}
  virtual int threadBody();
};
#endif // RDMA


// Global variables
static string progname;
static bool littleEndian;
static volatile bool quitflag = false;
static unsigned long pagesize;
static deque<string> commands;
static int nestingLevel = 0;
static int idleTime = -1;
static volatile bool collectStats = false;
static unsigned int mbufSize = 0;

static multimap<IpAddr, Target *> serverNodes;
static map<IpAddr, Target *> clientNodes;
static map<IpAddr, Target *> allNodes;

static int debugLevel = 0;
static UInt16 port = NSDPERF_PORT;
static UInt16 cmPort = 0;
static set<RdmaPortName> rdmaPortsOpt;
static int socksize = 0;
static int nWorkers = MSG_WORKERS;
static int nParallel = 1;
static enum RdmaMode { rOff, rOn, rAll, rInline } useRdma = rOff;
static int maxRdma = MAXRDMA_UNLIMITED;
static bool useCM = false;
#ifdef RDMA
static int rdmaDebugLevel = 0;
static bool rdmaInitialized = false;
static int path_mtu_value = 2048;
static enum ibv_mtu path_mtu = IBV_MTU_2048;
static int serviceLevel = 0;
#endif
static bool server = false;
static bool useipv6 = false;
static unsigned int nClients = 0;
static int addrFamily;
static int testTime = 10;
static unsigned int buffsize = DEF_BUFFSIZE;
static bool setMaxSend = false;
static bool setBuffSize = false;
static unsigned int nTesterThreads = TESTER_THREADS;
static bool showHist = false;
static bool verify = false;
static bool sinline = false;
static string plotFname;
static int remoteDebugLevel = -1;
static bool IAmServer = false;

static pthread_mutex_t logMutex;
static pthread_mutex_t globalMutex;
static pthread_cond_t globalCond;
static list<Thread *> deadThreads;
static unsigned int nThreadsStarted = 0;
static vector<Receiver *> receiverTab;
static vector<Receiver *>::iterator nextReceiver;
static MsgId nextMsgId = 1;
static unsigned int nReceiversRunning = 0;
static bool receiverRun = false;
static bool cmdInProgress = false;
static ListenAccept *laThreadP = NULL;
int TcpConn::nextCnum = 0;

static pthread_mutex_t workerMutex;
static pthread_cond_t workerCond;
static list<RcvMsg *> msgQueue;
static list<RcvMsg *> bulkQueue;
static vector<MsgWorker *> workerTab;
static int workersActive = 0;

static pthread_mutex_t testerMutex;
static pthread_cond_t testerCond;
static set<Tester *> testerTab;
static list<TestReq *> doneList;
static unsigned int nTestersWorking = 0;
static volatile bool testActive = false;


// Format of an entry in pending reply table
struct ReplyTabBucket
{
  pthread_mutex_t bucketMutex;
  ReplyEntry *bucketHeadP;
  ReplyEntry *freeListP;
  char pad[CACHE_LINE_SIZE - sizeof(pthread_mutex_t)
           - 2 * sizeof(ReplyEntry *)];

  ReplyTabBucket() : bucketHeadP(NULL), freeListP(NULL) {}
};


// Table of pending replies.  This is split into multiple buckets with a
// mutex for each one, since it is accessed by many threads at once.
static const int nRtBuckets = 64;
static ReplyTabBucket pendReplyTab[nRtBuckets];


// Get next word from string starting at pos.  Update pos to end of word.
static string getword(const string s, string::size_type &pos,
                      const char *delim = " \t\r")
{
  string::size_type pos1;

  pos1 = s.find_first_not_of(delim, pos);
  if (pos1 == string::npos)
  {
    pos = pos1;
    return "";
  }
  pos = s.find_first_of(delim, pos1);
  return s.substr(pos1, (pos == string::npos) ? pos : pos - pos1);
}


// Return true if start of line matches specified string
static bool match(const string line, const string s)
{
  return line.length() >= s.length() && line.substr(0, s.length()) == s;
}


// Split input string into separate command lines, delimited by semicolon
// or slash+space.
static void splitCmd(const string inp, deque<string> *linesP)
{
  int p1, p2, len = inp.length();
  for (p1 = 0; p1 < len; p1 = p2 + 1)
  {
    for (p2 = p1; p2 < len; p2++)
      if (inp[p2] == ';' ||
          (inp[p2] == '/' && p2 + 1 < len && inp[p2 + 1] == ' '))
        break;
    linesP->push_back(inp.substr(p1, p2 - p1));
    if (p2 < len && inp[p2] == '/')
      p2++;
  }
}


// Convert seconds to HTime
static HTime sectoht(int sec)
{ return sec * 1000000000LL; }


// Convert HTime to seconds
static double httosec(HTime t)
{ return t / 1000000000.0; }


// Convert HTime to milliseconds
static long long httomsec(HTime t)
{ return (t + 500000) / 1000000; }


// Convert HTime to printable string, leaving out the date portion
static string httostr(HTime t)
{
  ostringstream os;
  struct tm lt;
  time_t tsec = t / 1000000000;
  int nsec = t - 1000000000LL * tsec;
  if (localtime_r(&tsec, &lt) == NULL)
    Error("localtime_r");
  os << setw(2) << setfill('0') << lt.tm_hour << ":"
     << setw(2) << setfill('0') << lt.tm_min << ":"
     << setw(2) << setfill('0') << lt.tm_sec << "."
     << setw(6) << (nsec + 500) / 1000;
  return os.str();
}


// A hack to get an approximation of time stamp counter frequency
static int cpuMhz = 0;
static void initClock()
{
#ifdef __x86_64
  ifstream infile;
  string line, w;
  string::size_type pos;
  bool constantTsc = false;

  cpuMhz = 0;
  infile.open("/proc/cpuinfo");
  if (!infile)
    return;
  while (getline(infile, line))
  {
    if (match(line, "flags"))
    {
      for (pos = 0; pos != string::npos; )
        if (getword(line, pos) == "constant_tsc")
        {
          constantTsc = true;
          break;
        }
    }
    else if (match(line,"model name"))
    {
      for (pos = 0; pos != string::npos; )
      {
        w = getword(line, pos);
        if (w.length() >= 7 && w[1] == '.' && w.substr(4, 3) == "GHz")
        {
          w = w[0] + w.substr(2, 2);
          cpuMhz = atoi(w.c_str()) * 10000;
          break;
        }
      }
    }
    if (constantTsc && cpuMhz != 0)
      break;
  }
  infile.close();
  if (!constantTsc)
    cpuMhz = 0;
#endif
}


// Return current time of day
static HTime getTime()
{
#if _POSIX_TIMERS
  timespec ts;
  long rc = clock_gettime(CLOCK_REALTIME, &ts);
  if (rc != 0) Error("clock_gettime rc " << rc);
  return sectoht(ts.tv_sec) + ts.tv_nsec;
#else
  timeval tv;
  gettimeofday(&tv, NULL);
  return sectoht(tv.tv_sec) + tv.tv_usec * 1000;
#endif
}


// Get time stamp
static HTime getStamp()
{
#ifdef __x86_64
  UInt32 low, high;
  UInt64 tsc;
  if (cpuMhz == 0)
    return getTime();
  asm volatile("rdtsc" : "=a"(low), "=d"(high));
  tsc = (static_cast<UInt64>(high) << 32) | low;
  return (HTime)(tsc * (1000000.0 / cpuMhz));
#else
  return getTime();
#endif
}


// Sleep until specified time.  Return current time.
static HTime sleepUntil(HTime endTime)
{
  HTime now;
  for (now = getTime(); now < endTime; now = getTime())
    usleep((endTime - now) / 1000);
  return now;
}


// Swap bytes in a short
static UInt16 ByteSwap16(UInt16 d)
{
  return ((d >> 8) & 0x00FFU) |
         ((d << 8) & 0xFF00U);
}


// Swap bytes in a word
static UInt32 ByteSwap32(UInt32 d)
{
  return ((d >> 24) & 0x000000FFU) |
         ((d >>  8) & 0x0000FF00U) |
         ((d <<  8) & 0x00FF0000U) |
         ((d << 24) & 0xFF000000U);
}


// Swap bytes in a double word
static UInt64 ByteSwap64(UInt64 d)
{
  return ((d >> 56) & 0x00000000000000FFULL) |
         ((d >> 40) & 0x000000000000FF00ULL) |
         ((d >> 24) & 0x0000000000FF0000ULL) |
         ((d >>  8) & 0x00000000FF000000ULL) |
         ((d <<  8) & 0x000000FF00000000ULL) |
         ((d << 24) & 0x0000FF0000000000ULL) |
         ((d << 40) & 0x00FF000000000000ULL) |
         ((d << 56) & 0xFF00000000000000ULL);
}


// Report the number of online processors
static int numProcessors()
{
#ifndef _SC_NPROCESSORS_ONLN
  return 2;
#else
  return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}


// Set socket send/receive buffer sizes.  This routine must be called
// before listen or connect.
static void setSockSizes(Sock sock)
{
  if (socksize == 0)
    return;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &socksize, sizeof(socksize)) < 0)
    Warnm("setsockopt SO_RCVBUF failed");
  if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &socksize, sizeof(socksize)) < 0)
    Warnm("setsockopt SO_SNDBUF failed");
}


// Make a socket non-blocking
static void setSockNonblocking(Sock sock)
{
  int rc = ioctl(sock, (int)FIONBIO, (char *)&on, (int)sizeof(int));
  if (rc < 0)
    Errorm("ioctl FIONBIO");
}


// Get error message for a given error number
static string geterr(int e)
{
  char b[256];
  snprintf(b, sizeof(b), "error %d", e);
#ifdef __linux
  return strerror_r(e, b, sizeof(b));
#else
  (void) strerror_r(e, b, sizeof(b));
  return b;
#endif
}


// Round d to the specified number of significant decimal digits.
// Negative values are not supported.
static double siground(double d, int digits)
{
  int j, n;
  double tpow = 1.0;

  if (d <= 0.0 || digits <= 0) return 0.0;
  for (j = 0; j < digits; j++) tpow *= 10.0;

  // Normalize
  n = 0;
  if (d >= tpow) while (d >= tpow)        d /= 10.0, n--;
  else           while (d * 10.0 < tpow)  d *= 10.0, n++;

  // Round to precision
  d = floor(d + 0.5);

  // Undo normalize
  if (n > 0)      for (j = 0; j < n; j++)  d /= 10.0;
  else if (n < 0) for (j = 0; j < -n; j++) d *= 10.0;

  return d;
}


// Parse the RDMAPORTS command line option, and save it in rdmaPortsOpt array
static void parseRdmaPortsOpt(string optPorts)
{
  string portName, devName;
  string::size_type opos, ppos;
  int port, fabnum;

  for (opos = 0; opos != string::npos; )
  {
    // Extract a comma or space separated port name
    portName = getword(optPorts, opos, ", ");
    if (portName.empty())
      break;

    // Break up port name into colon or slash delimited sub-parts
    vector<string> word;
    for (ppos = 0; ppos != string::npos; )
    {
      string w = getword(portName, ppos, ":/");
      if (!w.empty())
        word.push_back(w);
    }
    if (word.size() < 1)
      Error("parseRdmaPorts failed");

    devName = word[0];
    port = (word.size() > 1) ? atoi(word[1].c_str()) : -1;
    fabnum = (word.size() > 2) ? atoi(word[2].c_str()) : 0;

    rdmaPortsOpt.insert(RdmaPortName(devName, port, fabnum));
  }
}


// Allocate a new data buffer for output.  If a big enough buffer is
// already allocated, just adjust the assigned buffer length.
void DataBuff::newBuff(unsigned int len)
{
  if (len == 0)
    Error("Allocating zero length buffer");

  bufflen = len;
  buffpos = 0;
  if (alloc > 0)
  {
    if (len <= alloc)
      return;
    delete [] buffP;
  }
  buffP = new char[len];
  alloc = len;
}


// Initialize buffer to point to specified data area
void DataBuff::initBuff(char *dataP, unsigned int datalen)
{
  if (alloc > 0)
  {
    delete [] buffP;
    alloc = 0;
  }
  buffP = dataP;
  bufflen = datalen;
  buffpos  = 0;
}


// Fill buffer with random data
void DataBuff::fillBuff(UInt64 seed)
{
  char *p;
  for (p = buffP; p - buffP + sizeof(UInt64) <= bufflen; p += sizeof(UInt64))
  {
    UInt64 *p64 = reinterpret_cast<UInt64 *>(p);
    *p64 = littleEndian ? seed : ByteSwap64(seed);
    seed += SCRAMBLE;
  }
  while (p < buffP + bufflen)
    *p++ = '\0';
}


// Verify buffer contents.  Return true if contents are correct.
bool DataBuff::verifyBuff(UInt64 seed)
{
  char *p;
  for (p = buffP; p - buffP + sizeof(UInt64) <= bufflen; p += sizeof(UInt64))
  {
    UInt64 *p64 = reinterpret_cast<UInt64 *>(p);
    if (*p64 != (littleEndian ? seed : ByteSwap64(seed)))
      return false;
    seed += SCRAMBLE;
  }
  while (p < buffP + bufflen)
    if (*p++ != '\0')
      return false;
  return true;
}


// Put a UInt16 item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putUInt16(UInt16 i)
{
  if (buffpos + sizeof(i) > bufflen) Error("putUInt16 buffer overflow");
  if (!littleEndian) i = ByteSwap16(i);
  memcpy(&buffP[buffpos], &i, sizeof(i));
  buffpos += sizeof(i);
}


// Put a Int32 item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putInt32(Int32 i)
{
  if (buffpos + sizeof(i) > bufflen) Error("putInt32 buffer overflow");
  if (!littleEndian) i = ByteSwap32(i);
  memcpy(&buffP[buffpos], &i, sizeof(i));
  buffpos += sizeof(i);
}


// Put a UInt32 item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putUInt32(UInt32 i)
{
  if (buffpos + sizeof(i) > bufflen) Error("putUInt32 buffer overflow");
  if (!littleEndian) i = ByteSwap32(i);
  memcpy(&buffP[buffpos], &i, sizeof(i));
  buffpos += sizeof(i);
}


// Put a UInt64 item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putUInt64(UInt64 i)
{
  if (buffpos + sizeof(i) > bufflen) Error("putUInt64 buffer overflow");
  if (!littleEndian) i = ByteSwap64(i);
  memcpy(&buffP[buffpos], &i, sizeof(i));
  buffpos += sizeof(i);
}


// Put an RdmaAddr item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putRdmaAddr(RdmaAddr a)
{
  putUInt64(a);
}


// Put an HTime item into buffer, performing endian conversion if
// necessary, and bump the buffer pointer.
void DataBuff::putHTime(HTime t)
{
  union { UInt64 i; HTime t; } u;
  u.t = t;
  if (buffpos + sizeof(u.i) > bufflen) Error("putHTime buffer overflow");
  if (!littleEndian) u.i = ByteSwap64(u.i);
  memcpy(&buffP[buffpos], &u.i, sizeof(u.i));
  buffpos += sizeof(u.i);
}


// Put an IpAddr into buffer and bump the buffer pointer.  No endian
// conversion is performed on the address data, since it is kept in memory
// in native byte order.
void DataBuff::putIpAddr(IpAddr iaddr)
{
  if (buffpos + sizeof(UInt32) + sizeof(iaddr.a) > bufflen)
    Error("putIpAddr buffer overflow");
  putUInt32(iaddr.fam);
  memcpy(&buffP[buffpos], iaddr.a, sizeof(iaddr.a));
  buffpos += sizeof(iaddr.a);
}


// Put string into buffer, with length and padding
void DataBuff::putString(string s)
{
  unsigned int slen = s.length();
  unsigned int padlen = 4 - (slen & 3);
  putUInt32(slen + padlen);
  if (buffpos + slen + padlen > bufflen) Error("putString buffer overflow");
  s.copy(&buffP[buffpos], slen);
  for (buffpos += slen; padlen > 0; padlen--)
    buffP[buffpos++] = '\0';
}


void DataBuff::putTimeLine(TimeLine *timeLine)
{
  putHTime(timeLine->rdStartStamp);
  putHTime(timeLine->rdFinStamp);
  putHTime(timeLine->msgSendStamp);
  putHTime(timeLine->msgRecvStamp);
  putHTime(timeLine->replySendStamp);
  putHTime(timeLine->replyRecvStamp);
}


// Get UInt32 from buffer
UInt32 DataBuff::getUInt32()
{
  UInt32 i;
  if (buffpos + sizeof(i) > bufflen) Error("getUInt32 buffer underflow");
  memcpy(&i, &buffP[buffpos], sizeof(i));
  buffpos += sizeof(i);
  return littleEndian ? i : ByteSwap32(i);
}


// Get UInt16 from buffer
UInt16 DataBuff::getUInt16()
{
  UInt16 i;
  if (buffpos + sizeof(i) > bufflen) Error("getUInt16 buffer underflow");
  memcpy(&i, &buffP[buffpos], sizeof(i));
  buffpos += sizeof(i);
  return littleEndian ? i : ByteSwap16(i);
}


// Get Int32 from buffer
Int32 DataBuff::getInt32()
{
  Int32 i;
  if (buffpos + sizeof(i) > bufflen) Error("getInt32 buffer underflow");
  memcpy(&i, &buffP[buffpos], sizeof(i));
  buffpos += sizeof(i);
  return littleEndian ? i : ByteSwap32(i);
}


// Get UInt64 from buffer
UInt64 DataBuff::getUInt64()
{
  UInt64 i;
  if (buffpos + sizeof(i) > bufflen) Error("getUInt64 buffer underflow");
  memcpy(&i, &buffP[buffpos], sizeof(i));
  buffpos += sizeof(i);
  return littleEndian ? i : ByteSwap64(i);
}


// Get RdmaAddr from buffer
RdmaAddr DataBuff::getRdmaAddr()
{
  return getUInt64();
}


// Get HTime from buffer
HTime DataBuff::getHTime()
{
  union { UInt64 i; HTime t; } u;
  if (buffpos + sizeof(u.i) > bufflen) Error("getHTime buffer underflow");
  memcpy(&u.i, &buffP[buffpos], sizeof(u.i));
  buffpos += sizeof(u.i);
  if (!littleEndian) u.i = ByteSwap64(u.i);
  return u.t;
}


// Get IpAddr from buffer
IpAddr DataBuff::getIpAddr()
{
  IpAddr iaddr;
  if (buffpos + sizeof(UInt32) + sizeof(iaddr.a) > bufflen)
    Error("getIpAddr buffer underflow");
  iaddr.fam = static_cast<Atype>(getUInt32());
  memcpy(iaddr.a, &buffP[buffpos], sizeof(iaddr.a));
  buffpos += sizeof(iaddr.a);
  return iaddr;
}


// Get string from buffer
string DataBuff::getString()
{
  unsigned int slen = getUInt32();
  if (buffpos + slen > bufflen) Error("getString buffer underflow");
  string s(&buffP[buffpos]);
  if (s.length() >= slen) Error("incorrect getString length");
  buffpos += slen;
  return s;
}

TimeLine* DataBuff::getTimeLine()
{
  TimeLine *timeLine = new TimeLine();
  timeLine->rdStartStamp = getHTime();
  timeLine->rdFinStamp = getHTime();
  timeLine->msgSendStamp = getHTime();
  timeLine->msgRecvStamp = getHTime();
  timeLine->replySendStamp = getHTime();
  timeLine->replyRecvStamp = getHTime();
  return timeLine;
}


// Calculate buffer space needed to do putString
static unsigned int calcLen(string s)
{
  unsigned int slen = s.length();
  unsigned int padlen = 4 - (slen & 3);
  return sizeof(UInt32) + slen + padlen;
}


// Construct RdmaPortInfo from an RdmaPort.  The CM port is taken from
// global setting, so RDMA must already be initialized before calling this.
#ifdef RDMA
RdmaPortInfo::RdmaPortInfo(const RdmaPort *rP) :
  piName(rP->pdevP->rdmaDevName), piPort(rP->rdmaPortnum),
  piFabnum(rP->rdmaFabnum), piPortIf(rP->portIf), piAddr(rP->portAddr),
  piCmPort(cmPort) {}
#endif


// Calculate buffer space needed to hold RdmaPortInfo object
unsigned int RdmaPortInfo::calcPortInfoLen() const
{
  return calcLen(piName) + 2 * sizeof(Int32) + sizeof(UInt64) +
    piAddr.getSize() + sizeof(UInt16);
}


// Put RdmaPortInfo into buffer and bump the buffer pointer
void RdmaPortInfo::putBuff(DataBuff *dbP) const
{
  dbP->putString(piName);
  dbP->putInt32(piPort);
  dbP->putInt32(piFabnum);
  dbP->putUInt64(piPortIf);
  dbP->putIpAddr(piAddr);
  dbP->putUInt16(piCmPort);
}


// Get RdmaPortInfo from buffer
void RdmaPortInfo::getBuff(DataBuff *dbP)
{
  piName = dbP->getString();
  piPort = dbP->getInt32();
  piFabnum = dbP->getInt32();
  piPortIf = dbP->getUInt64();
  piAddr = dbP->getIpAddr();
  piCmPort = dbP->getUInt16();
}


// Convert port interface ID to string
static string portIfToString(UInt64 pif)
{
  ostringstream os;
  int j;
  pif = ByteSwap64(pif);
  for (j = 0; j < 4; j++)
  {
    unsigned int n = (pif & 0xffff000000000000ULL) >> 48;
    os << setw(4) << setfill('0') << hex << n;
    if (j < 3) os << ":";
    pif <<= 16;
  }
  return os.str();
}


// Convert RdmaPortInfo to printable string for messages
string RdmaPortInfo::toString() const
{
  ostringstream os;
  os << piName << ":" << piPort;
  if (piFabnum != 0)
    os << ":" << piFabnum;
  if (!piAddr.isNone())
    os << " " << piAddr.toString();
  if (piPortIf != 0)
    os << " " << portIfToString(piPortIf);
  return os.str();
}


// Put Histogram into buffer and bump the buffer pointer
void Histogram::putBuff(DataBuff *dbP) const
{
  map<HTime, UInt32>::const_iterator b;
  dbP->putUInt64(totalTime);
  dbP->putUInt32(nEvents);
  dbP->putUInt32(buckets.size());
  for (b = buckets.begin(); b != buckets.end(); ++b)
  {
    dbP->putHTime(b->first);
    dbP->putUInt32(b->second);
  }
}


// Get Histogram from buffer
void Histogram::getBuff(DataBuff *dbP)
{
  unsigned int nb;
  HTime bnum;
  UInt32 count;
  buckets.clear();
  totalTime = dbP->getUInt64();
  nEvents = dbP->getUInt32();
  for (nb = dbP->getUInt32(); nb > 0; nb--)
  {
    bnum = dbP->getHTime();
    count = dbP->getUInt32();
    buckets[bnum] = count;
  }
}


// Structure to hold CPU utilization statistics in ticks
struct CpuStats
{
  UInt64 user, system, idle, iowait, other;
  UInt64 total() { return user + system + idle + iowait + other; }
};


// Get CPU utilization statistics.  Return false if not supported.
static bool getStats(CpuStats *statsP)
{
  static bool supported = true;
  if (!supported)
    return false;

#ifdef _AIX
  perfstat_partition_total_t pstats;
  if (perfstat_partition_total(NULL, &pstats, sizeof(pstats), 1) < 0)
    Errorm("perfstat_partition_total");

  // More work is required to calculate utilization for LPAR in shared mode,
  // so punt for now.
  if (pstats.type.b.shared_enabled)
  {
    supported = false;
    return false;
  }

  statsP->user   = pstats.puser;
  statsP->system = pstats.psys;
  statsP->idle   = pstats.pidle;
  statsP->iowait = pstats.pwait;
  statsP->other  = 0;
  return true;

#else
  ifstream infile;
  string line;
  UInt64 n[8];
  bool gotit = false;

  // Get CPU info from /proc/stat.  See Documentation/filesystems/proc.txt
  // in the Linux kernel source.
  infile.open("/proc/stat");
  if (!infile)
  {
    supported = false;
    return false;
  }
  while (getline(infile, line))
  {
    // Fields are: user nice system idle iowait irq softirq steal
    if (sscanf(line.c_str(), "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7]) == 8)
    {
      gotit = true;
      break;
    }

    // Older kernels didn't have the steal field
    n[7] = 0;
    if (sscanf(line.c_str(), "cpu %llu %llu %llu %llu %llu %llu %llu",
               &n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]) == 7)
    {
      gotit = true;
      break;
    }
  }
  infile.close();
  if (!gotit)
  {
    supported = false;
    return false;
  }

  statsP->user   = n[0] + n[1];
  statsP->system = n[2];
  statsP->idle   = n[3];
  statsP->iowait = n[4];
  statsP->other  = n[5] + n[6] + n[7];
  return true;
#endif
}


// Return CPU idle percentage since previous call, or -1 if not supported
// on this OS or if this is the first call.
static int cpuIdle()
{
  static bool initialized = false;
  static CpuStats oldstats;
  CpuStats stats;
  UInt64 tot;
  int val = -1;

  if (!getStats(&stats))
    return -1;

  if (initialized)
  {
    tot = stats.total() - oldstats.total();
    if (tot != 0)
      val = (stats.idle - oldstats.idle) * 100 / tot;
  }
  else
    initialized = true;

  oldstats = stats;
  return val;
}


// Convert hostname and IP address to a string for output messages
static string hostString(const string hname, const IpAddr iaddr)
{
  int rc;
  sockaddr_storage saddr;

  // Determine whether the host name is a dotted decimal or hex IP address
  // by trying to convert it to a network address structure.  If the
  // conversion is successful, then don't show the IP address in result,
  // since that would be redundant.
  rc = inet_pton(iaddr.getFamily(), hname.c_str(), &saddr);
  if (rc < 0)
    Errorm("inet_pton");
  else if (rc == 0)
    return hname + " (" + iaddr.toString() + ")";
  return hname;
}


// Error-checking wrappers for mutex and condition variable routines
static void thInitMutex(pthread_mutex_t *mutexP)
{ if (pthread_mutex_init(mutexP, NULL) != 0) Errorm("pthread_mutex_init"); }

static void thInitCond(pthread_cond_t *condP)
{ if (pthread_cond_init(condP, NULL) != 0) Errorm("pthread_cond_init"); }

static void thLock(pthread_mutex_t *mutexP)
{ if (pthread_mutex_lock(mutexP) != 0) Errorm("pthread_mutex_lock"); }

static void thUnlock(pthread_mutex_t *mutexP)
{ if (pthread_mutex_unlock(mutexP) != 0) Errorm("pthread_mutex_unlock"); }

static void thWait(pthread_cond_t *condP, pthread_mutex_t *mutexP)
{ if (pthread_cond_wait(condP, mutexP) != 0) Errorm("pthread_cond_wait"); }

static void thSignal(pthread_cond_t *condP)
{ if (pthread_cond_signal(condP) != 0) Errorm("pthread_cond_signal"); }

static void thBcast(pthread_cond_t *condP)
{ if (pthread_cond_broadcast(condP) != 0) Errorm("pthread_cond_broadcast"); }

static void thJoin(pthread_t th, void **valPP)
{ if (pthread_join(th, valPP) != 0) Errorm("pthread_join"); }

static void thKill(pthread_t th, int sig)
{ if (pthread_kill(th, sig) != 0) Errorm("pthread_kill"); }


// Return a random 64-bit number
static UInt64 randSeed()
{
  // Should use random_r here, but not all operating systems have that
  thLock(&globalMutex);
  UInt64 w = random();
  w = (w << 32) + random();
  thUnlock(&globalMutex);
  return w;
}


// Compare two IP addresses
bool IpAddr::operator<(const IpAddr &iaddr) const
{
  unsigned int j;
  if (fam != iaddr.fam)
    return fam < iaddr.fam;
  for (j = 0; j < sizeof(a); j++)
    if (a[j] != iaddr.a[j])
      return a[j] < iaddr.a[j];
  return false;
}


// Test inequality of two IP addresses
bool IpAddr::operator!=(const IpAddr &iaddr) const
{
  unsigned int j;
  if (fam != iaddr.fam)
    return true;
  for (j = 0; j < sizeof(a); j++)
    if (a[j] != iaddr.a[j])
      return true;
  return false;
}


// Clear IP address
void IpAddr::setNone()
{
  in_addr_t addr = INADDR_NONE;
  fam = AT_IPV4;
  memset(a, 0, sizeof(a));
  memcpy(a, &addr, sizeof(addr));
}


// Set IP address to accept any incoming messages
void IpAddr::setAny()
{
  memset(a, 0, sizeof(a));
#ifdef IPV6_SUPPORT
  if (useipv6)
  {
    fam = AT_IPV6;
    memcpy(a, &in6addr_any, sizeof(in6addr_any));
  }
  else
#endif
  {
    in_addr_t addr = INADDR_ANY;
    fam = AT_IPV4;
    memcpy(a, &addr, sizeof(addr));
  }
}


// Convert a host name string to an IP address.  If an error occurs, log an
// error message and return E_INVAL.
Errno IpAddr::parse(const string hostname)
{
  string::size_type pos = 0;
  string hname = getword(hostname, pos);
#ifdef IPV6_SUPPORT
  addrinfo hints, *resP;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = addrFamily;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(hname.c_str(), NULL, &hints, &resP);
  if (rc != 0)
  {
    Log("Invalid hostname \"" << hname << "\": " << gai_strerror(rc));
    return E_INVAL;
  }

  // Copy the address data.  If multiple addresses are returned, we only
  // use the first one.  It would be better to try all of them until a
  // working address is found.
  loadSockaddr(resP->ai_addr);

  freeaddrinfo(resP);
#else
  unsigned int d[4];
  fam = AT_IPV4;
  memset(a, 0, sizeof(a));
  if (sscanf(hname.c_str(), "%u.%u.%u.%u", &d[0], &d[1], &d[2], &d[3]) == 4)
  {
    if (d[0] > 255 || d[1] > 255 || d[2] > 255 || d[3] > 255)
    {
      Log("Invalid hostname: " << hname);
      return E_INVAL;
    }
    a[0] = d[0]; a[1] = d[1]; a[2] = d[2]; a[3] = d[3];
  }
  else
  {
    hostent *hp = gethostbyname(hname.c_str());
    if (hp == NULL || hp->h_addrtype != AF_INET || hp->h_length != 4)
    {
      Log("Cannot find " << hname);
      return E_INVAL;
    }
    memcpy(a, hp->h_addr, 4);
  }
#endif
  return E_OK;
}


// Load IpAddr contents from a sockaddr struct
void IpAddr::loadSockaddr(const sockaddr *saddrP)
{
  switch (saddrP->sa_family)
  {
#ifdef IPV6_SUPPORT
    case AF_INET6:
      fam = AT_IPV6;
      memcpy(a, &reinterpret_cast<const sockaddr_in6 *>(saddrP)->sin6_addr,
             sizeof(a));
      break;
#endif

    case AF_INET:
      fam = AT_IPV4;
      memset(a, 0, sizeof(a));
      memcpy(a, &reinterpret_cast<const sockaddr_in *>(saddrP)->sin_addr,
             sizeof(in_addr_t));
      break;

    default:
      Error("Invalid sa_family");
      break;
  }
}


// Convert IP address to printable string
string IpAddr::toString() const
{
#ifdef IPV6_SUPPORT
  char buf[INET6_ADDRSTRLEN];
#else
  char buf[INET_ADDRSTRLEN];
#endif
  if (inet_ntop(getFamily(), &a, buf, sizeof(buf)) == NULL)
    Errorm("inet_ntop");
  return buf;
}


// Create a sockaddr struct in the supplied buffer area using this IP
// address and the specified port.  Return a pointer to the buffer.
sockaddr *IpAddr::toSockaddr(UInt16 port, sockaddr_storage *sockBuffP) const
{
  union
  {
    sockaddr_storage ss;
    sockaddr_in sin;
#ifdef IPV6_SUPPORT
    sockaddr_in6 sin6;
#endif
  } u;

  memset(&u, 0, sizeof(u));
#ifdef IPV6_SUPPORT
  if (fam == AT_IPV6)
  {
    u.sin6.sin6_family = getFamily();
    memcpy(&u.sin6.sin6_addr, a, sizeof(sockaddr_in6));
    u.sin6.sin6_port = htons(port);
  }
  else
#endif
  {
    u.sin.sin_family = getFamily();
    memcpy(&u.sin.sin_addr, a, sizeof(sockaddr_in));
    u.sin.sin_port = htons(port);
  }
  memcpy(sockBuffP, &u.ss, sizeof(sockaddr_storage));
  return reinterpret_cast<sockaddr *>(sockBuffP);
}


// Return the length of a sockaddr constructed from this IP address
socklen_t IpAddr::getSocklen() const
{
#ifdef IPV6_SUPPORT
  if (fam == AT_IPV6)
    return sizeof(sockaddr_in6);
#endif
  return sizeof(sockaddr_in);
}


// Return true if this is a link-local IPv6 address
bool IpAddr::isLinkLocal() const
{
#ifdef IPV6_SUPPORT
  if (fam != AT_IPV6)
    return false;
  union { sockaddr_storage ss; sockaddr_in6 sin6; } u;
  toSockaddr(0, &u.ss);
  return IN6_IS_ADDR_LINKLOCAL(&u.sin6.sin6_addr);
#else
  return false;
#endif
}


// Return true if the IP address has not been set
bool IpAddr::isNone() const
{
  if (fam != AT_IPV4)
    return false;
  union { sockaddr_storage ss; sockaddr_in sin; } u;
  toSockaddr(0, &u.ss);
  return u.sin.sin_addr.s_addr == INADDR_NONE;
}


// Add an entry to the pending reply table
static void addReply(MsgId m, MsgRecord *mrP, TcpConn *connP)
{
  ReplyEntry *reP;
  int b = m % nRtBuckets;
  thLock(&pendReplyTab[b].bucketMutex);
  if (pendReplyTab[b].freeListP != NULL)
  {
    reP = pendReplyTab[b].freeListP;
    pendReplyTab[b].freeListP = reP->reNextP;
    reP->msgId = m;
    reP->mrP = mrP;
    reP->connP = connP;
    reP->reNextP = NULL;
  }
  else
    reP = new ReplyEntry(m, mrP, connP);
  reP->reNextP = pendReplyTab[b].bucketHeadP;
  pendReplyTab[b].bucketHeadP = reP;
  thUnlock(&pendReplyTab[b].bucketMutex);
}


// Look up an entry in the pending reply table using the unique global
// message ID as key.  If removeIt is true, then remove entry from table.
static MsgRecord *getReply(MsgId m, bool removeIt)
{
  ReplyEntry *reP, *prevReP;
  MsgRecord *mrP;
  int b = m % nRtBuckets;
  thLock(&pendReplyTab[b].bucketMutex);
  prevReP = NULL;
  for (reP = pendReplyTab[b].bucketHeadP; reP != NULL; reP = reP->reNextP)
  {
    if (reP->msgId == m)
      break;
    prevReP = reP;
  }
  if (reP == NULL)
    Error("reply not found in pending reply table");
  mrP = reP->mrP;
  if (removeIt)
  {
    if (prevReP == NULL)
      pendReplyTab[b].bucketHeadP = reP->reNextP;
    else
      prevReP->reNextP = reP->reNextP;
    reP->reNextP = pendReplyTab[b].freeListP;
    pendReplyTab[b].freeListP = reP;
  }
  thUnlock(&pendReplyTab[b].bucketMutex);
  return mrP;
}


#ifdef RDMA
// RDMA data
static vector<RdmaDevice *> rdmaDevTab;
static vector<RdmaPort *> rdmaPortTab;
static ibv_context **cmCtxPP = NULL;
static rdma_event_channel *cmChan = NULL;
static RdmaConn *cmListenConnP = NULL;
static map<ConnKey, rdma_cm_event *> cmConnRequests;
static RdmaAsync *rdmaAsyncThreadP = NULL;
static RdmaCM *rdmaCMThreadP = NULL;
static thState rdmaAsyncState = tsRun;  // State of RDMA async thread
static thState rdmaCMState = tsRun;     // State of RDMA CM thread
static char *memoryPoolP = NULL;        // Registered memory pool
static RdmaAddr memoryPoolBase;         // Base address for buffers in pool
static Int64 memoryPoolLen;             // Length of the memory pool
static unsigned int poolCount;          // Count of buffers in the pool
static unsigned int poolBuffsize;       // Size of a buffer in the pool
static list<char *> poolList;           // List of free memory buffers
static unsigned int mbufCount;          // Count of message buffers in the pool
static unsigned int mbufBuffsize;       // Size of a message buffer in the pool
static list<char *> mbufList;           // List of free message buffers


// Free the RDMA memory pool if it was allocated
static void rdmaMemoryFree()
{
  if (memoryPoolP == NULL)
    return;
  if (poolList.size() != poolCount || mbufList.size() != mbufCount)
    Error("RDMA memory pool freed while buffers in use");
  vector<RdmaDevice *>::iterator rdi;
  for (rdi = rdmaDevTab.begin(); rdi != rdmaDevTab.end(); ++rdi)
  {
    RdmaDevice *rdevP = *rdi;
    if (rdevP->ibMR != NULL && ibv_dereg_mr(rdevP->ibMR) != 0)
      Errorm("ibv_dereg_mr failed");
    rdevP->ibMR = NULL;
  }
  delete [] memoryPoolP;
  memoryPoolP = NULL;
  poolList.clear();
  mbufList.clear();
}


// Allocate a memory pool for use with RDMA.
static void rdmaMemoryAlloc(int nConnections)
{
  unsigned int n;

  if (memoryPoolP != NULL)
    Error("RDMA memory pool already allocated");

  // On server nodes, RDMA buffers are needed to respond to read or write
  // operations initiated by tester threads on clients.  We allocate enough
  // buffers up front so that a buffer will always be available for any
  // request.  The requests are:
  //    1) read - Each worker thread needs a buffer to act as the source
  //       of test data to RDMA write to client in reply (rtestBuff).
  //    2) nwrite - Worker threads do RDMA read from a buffer on the client,
  //       but they need a local target buffer (rdBuffP).
  //    3) write - The client manages these and writes into them directly.
  //       They are allocated by the client sending an RdmaGetBuffs RPC.
  //       The client remembers them in remoteBuffs, and the server keeps
  //       track of them in givenBuffs.  Clients ask for a buffer for each
  //       tester thread on each connection.  In theory, buffers used by
  //       parallel connections could be shared on a client, but it is
  //       simpler to treat the connections as being separate server nodes
  //       and thus get a separate pool of buffers for each one.
  //
  // On client nodes, RDMA buffers are needed for:
  //    1) read - Each tester thread allocates a buffer (dataP) whose address
  //       will be sent to the server for it to write into.
  //    2) nwrite, write - One buffer per tester (testBuff).  For write
  //       requests, the client does an RDMA write.  For nwrite, the address
  //       of this buffer is sent to the server, who does an RDMA read.
  if (IAmServer)
  {
    poolCount = nWorkers * 2 + nTesterThreads * nClients * nParallel;
    if (rdmaDebugLevel > 0)
    {
      printf("rdmaMemoryAlloc: server "
             "poolCount = nWorkers (%d) * 2 + nTesterThreads (%d) * nClients (%d) * nParallel (%d) = %u\n",
             nWorkers, nTesterThreads, nClients, nParallel, poolCount);
    }
  }
  else
  {
    poolCount = nTesterThreads * 2;
    if (rdmaDebugLevel > 0)
    {
      printf("rdmaMemoryAlloc: client "
             "poolCount = nTesterThreads (%d) * 2 = %d\n",
             nTesterThreads, poolCount);
    }
  }

  // Message buffers in registered memory (mbufs) are used for sending and
  // receiving when RDMA is set to "all" or "inline".  These are allocated
  // up front.  Unlike data buffers, which are shared by all devices, we
  // need a separate allocation of mbufs for each connection to post
  // receives.  We allocate one mbuf for each tester for each connection.
  // In addition, servers need an mbuf per worker for sending replies,
  // and clients need an mbuf per tester for sending request RPCs.
  if (useRdma == rAll || useRdma == rInline)
  {
    mbufCount = (IAmServer ? nWorkers : nTesterThreads) + nConnections * nTesterThreads;
    if (rdmaDebugLevel > 0)
    {
      if (IAmServer)
      {
        printf("rdmaMemoryAlloc: server "
               "mbufCount = nWorkers (%d) + nConnections (%d) * nTesterThreads (%d) = %u\n",
               nWorkers, nConnections, nTesterThreads, mbufCount);
      }
      else
      {
        printf("rdmaMemoryAlloc: client "
               "mbufCount = nTesterThreads (%d) + nConnections (%d) * nTesterThreads (%d) = %u\n",
               nTesterThreads, nConnections, nTesterThreads, mbufCount);
      }
    }
  }
  else
  {
    mbufCount = 0;
  }

  // When sending data buffers inline, an mbuf must be big enough to read
  // the whole thing.
  mbufSize = MSG_HDRSIZE + MAX_RPCSIZE;
  if (useRdma == rInline)
    mbufSize += buffsize;

  // Create a memory pool of page-aligned buffers.  These don't really have
  // to be page-aligned, but it might reduce contention between threads
  // (although the chances that this will make any difference are slim).
  poolBuffsize = (buffsize + pagesize - 1) / pagesize * pagesize;
  mbufBuffsize = (mbufSize + pagesize - 1) / pagesize * pagesize;
  memoryPoolLen = static_cast<Int64>(poolBuffsize) * poolCount +
                  static_cast<Int64>(mbufBuffsize) * mbufCount;
  memoryPoolP = NULL;
  posix_memalign((void**)&memoryPoolP,
                 16 * 1024 * 1024,
                 memoryPoolLen);
  if (rdmaDebugLevel > 0)
  {
    printf("rdmaMemoryAlloc: memoryPoolP start 0x%llX end 0x%llX "
           "memoryPoolLen %lld poolBuffsize %u mbuffBuffsize %u\n",
           memoryPoolP, memoryPoolP + memoryPoolLen,
           memoryPoolLen, poolBuffsize, mbufBuffsize);
  }
  if (memoryPoolP == NULL)
    Error("RDMA memory pool allocation failed");
  memset(memoryPoolP, 0, memoryPoolLen);
  char *poolPosP = memoryPoolP;

  memoryPoolBase = RdmaAddr(memoryPoolP);

  // Register the entire pool on each device
  int accFlags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
    IBV_ACCESS_REMOTE_WRITE;
  vector<RdmaDevice *>::iterator rdi;
  for (rdi = rdmaDevTab.begin(); rdi != rdmaDevTab.end(); ++rdi)
  {
    RdmaDevice *rdevP = *rdi;

    // Skip this device if it had no active ports
    if (rdevP->ibCC == NULL)
      continue;

    if (rdmaDebugLevel > 0)
    {
      printf("rdmaMemoryAlloc: poolPosP start 0x%llX end 0x%llX memoryPoolLen %lld\n",
             poolPosP, poolPosP + memoryPoolLen, memoryPoolLen);
    }
    rdevP->ibMR = ibv_reg_mr(rdevP->ibPD, poolPosP, memoryPoolLen, accFlags);
    if (rdevP->ibMR == NULL) Errorm("ibv_reg_mr failed");
  }

  // Initialize free space list
  for (n = 0; n < poolCount; n++)
  {
    poolList.push_back(poolPosP);
    poolPosP += poolBuffsize;
  }
  for (n = 0; n < mbufCount; n++)
  {
    mbufList.push_back(poolPosP);
    poolPosP += mbufBuffsize;
  }
}


// Get some memory for a data buffer.  If RDMA is initialized, get it from
// from the RDMA memory pool.  Otherwise get from heap.
static char *poolGet(unsigned int len)
{
  char *buffP;

  if (!rdmaInitialized)
    return new char[len];
  if (memoryPoolP == NULL)
    Error("memory pool not initialized");
  if (len > poolBuffsize)
    Error("incorrect length in memory pool request");
  thLock(&globalMutex);
  if (poolList.empty())
    Error("memory pool exhausted");
  buffP = poolList.front();
  poolList.pop_front();
  thUnlock(&globalMutex);
  return buffP;
}


// Give back some memory that was allocated with poolGet.
static void poolFree(char *buffP)
{
  if (buffP == NULL)
    return;
  if (!rdmaInitialized)
  {
    delete [] buffP;
    return;
  }
  if (memoryPoolP == NULL)
    Error("memory pool not initialized");
  thLock(&globalMutex);
  poolList.push_back(buffP);
  thUnlock(&globalMutex);
}


// Get some memory for a message buffer for RDMA send and receive requests.
static char *mbufGet(unsigned int len)
{
  char *mbufP;
  if (!rdmaInitialized)
    Error("message buffer allocated without initializing RDMA");
  if (memoryPoolP == NULL)
    Error("memory pool not initialized");
  if (len > mbufBuffsize)
    Error("incorrect length in message buffer request");
  thLock(&globalMutex);
  if (mbufList.empty())
    Error("message buffer pool exhausted");
  mbufP = mbufList.front();
  mbufList.pop_front();
  thUnlock(&globalMutex);
  return mbufP;
}


// Give back some memory that was allocated with mbufGet.
static void mbufFree(char *mbufP)
{
  if (mbufP == NULL)
    return;
  if (!rdmaInitialized)
    Error("message buffer freed without initializing RDMA");
  if (memoryPoolP == NULL)
    Error("memory pool not initialized");
  thLock(&globalMutex);
  mbufList.push_back(mbufP);
  thUnlock(&globalMutex);
}


// Kill one of the RDMA threads.  Global mutex must be held.
static void killThread(Thread *thP, thState *tsP)
{
  if (thP == NULL)
    return;
  *tsP = tsDie;
  thKill(thP->getThread(), SIGUSR1);
  while (*tsP != tsDead)
    thWait(&globalCond, &globalMutex);
}


// Kill RDMA threads and wait for them to go away
static void rdmaKillThreads()
{
  vector<RdmaDevice *>::iterator rdi;
  thLock(&globalMutex);
  for (rdi = rdmaDevTab.begin(); rdi != rdmaDevTab.end(); ++rdi)
  {
    killThread((*rdi)->rdmaRcvThreadP, &(*rdi)->rdmaRcvState);
    (*rdi)->rdmaRcvThreadP = NULL;
  }
  killThread(rdmaAsyncThreadP, &rdmaAsyncState);
  rdmaAsyncThreadP = NULL;
  killThread(rdmaCMThreadP, &rdmaCMState);
  rdmaCMThreadP = NULL;
  thUnlock(&globalMutex);

  if (cmListenConnP != NULL)
  {
    cmListenConnP->rdDisconnect();
    delete cmListenConnP;
    cmListenConnP = NULL;
  }
}


// Shut down RDMA, closing all devices
static void rdmaShutdown()
{
  if (!rdmaInitialized)
    return;

  rdmaKillThreads();
  rdmaMemoryFree();

  int e;
  while (!rdmaDevTab.empty())
  {
    RdmaDevice *rdevP = rdmaDevTab.back();
    rdevP->destroyCQ();
    if (rdevP->ibPD != NULL)
    {
      e = ibv_dealloc_pd(rdevP->ibPD);
      if (e != 0)
        Error("ibv_dealloc_pd failed: " << geterr(e));
    }
    if (rdevP->ibCC != NULL)
    {
      e = ibv_destroy_comp_channel(rdevP->ibCC);
      if (e != 0)
        Error("ibv_destroy_comp_channel failed: " << geterr(e));
    }
    if (!useCM && ibv_close_device(rdevP->ibContext) != 0)
      Errorm("ibv_close_device falied");
    delete rdevP;
    rdmaDevTab.pop_back();
  }
  while (!rdmaPortTab.empty())
  {
    delete rdmaPortTab.back();
    rdmaPortTab.pop_back();
  }
  if (cmChan != NULL)
  {
    rdma_destroy_event_channel(cmChan);
    cmChan = NULL;
  }
  if (cmCtxPP != NULL)
  {
    rdma_free_devices(cmCtxPP);
    cmCtxPP = NULL;
  }
  rdmaInitialized = false;
}


// Get a list of the active network interface addresses on this node
static void getIfconf(vector<NetIface> *netInterfacesP)
{
  struct ifaddrs *ifP, *ifaddr = NULL;
  unsigned short fam;
  NetIface nif;

  if (getifaddrs(&ifaddr) < 0)
    Errorm("getifaddrs");

  for (ifP = ifaddr; ifP != NULL; ifP = ifP->ifa_next)
  {
    if (ifP->ifa_addr == NULL || (ifP->ifa_flags & IFF_UP) == 0)
      continue;

    fam = ifP->ifa_addr->sa_family;
#ifdef IPV6_SUPPORT
    if (fam != AF_INET && fam != AF_INET6)
      continue;
#else
    if (fam != AF_INET)
      continue;
#endif

    nif.addr.loadSockaddr(ifP->ifa_addr);
    nif.ifName = ifP->ifa_name;
    netInterfacesP->push_back(nif);
  }
  freeifaddrs(ifaddr);
}


// Open RDMA devices and initialize them if necessary.  This must be called
// after test parameters have been established, since it uses those
// parameters to adjust queue sizes.  Returns error message if failure.
static string rdmaStart()
{
  string errmsg;
  int j, p, fabnum, numDevices;
  ibv_device **devList = NULL;
  vector<RdmaDevice *>::iterator rdi;
  ibv_port_attr portAttr;
  vector<NetIface> netInterfaces;
  vector<NetIface>::const_iterator ni;
  int ioctl_sock = -1;

  if (rdmaInitialized)
    goto exit;
  if (nClients == 0)
    Error("RDMA start with no clients");
  if (!rdmaDevTab.empty())
    Error("RDMA start with rdmaDevTab not empty");
  if (!rdmaPortTab.empty())
    Error("RDMA start with rdmaPortTab not empty");

  // Set memory locking limits to the maximum allowed
  rlimit rlim;
  if (getrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
    Errorm("getrlimit RLIMIT_MEMLOCK failed");
  rlim.rlim_cur = rlim.rlim_max;
  if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
    Errorm("setrlimit RLIMIT_MEMLOCK to" << rlim.rlim_cur << " failed");

  // Open all RDMA devices, creating an rdmaDevTab entry for each of them.
  if (useCM)
  {
    cmCtxPP = rdma_get_devices(&numDevices);
    if (cmCtxPP == NULL)
    {
      if (errno != ENOSYS)
        Errorm("rdma_get_devices failed");
      errmsg = "RDMA is not available";
      goto exit;
    }
    if (numDevices <= 0)
    {
      errmsg = "No RDMA ports found";
      goto exit;
    }
    rdmaDevTab.reserve(numDevices);
    for (j = 0; j < numDevices; j++)
      rdmaDevTab.push_back(new RdmaDevice(cmCtxPP[j]));

    getIfconf(&netInterfaces);
  }
  else
  {
    devList = ibv_get_device_list(&numDevices);
    if (devList == NULL)
    {
      if (errno != ENOSYS)
        Errorm("ibv_get_device_list failed");
      errmsg = "RDMA is not available";
      goto exit;
    }
    rdmaDevTab.reserve(numDevices);
    for (j = 0; j < numDevices; j++)
    {
      ibv_device *devP = devList[j];
      ibv_context *ctx = ibv_open_device(devP);
      if (ctx == NULL)
      {
        string rdmaDevName = ibv_get_device_name(devP);
        errmsg = "Open of RDMA device " + rdmaDevName + " failed";
        goto exit;
      }
      rdmaDevTab.push_back(new RdmaDevice(ctx));
    }
  }

  // Loop through all RDMA devices, enumerating their active ports.
  // If the "-r RDMAPORTS" option was given, use that as a filter to
  // skip any ports that do not match.  Add the rest to rdmaPortTab.
  for (rdi = rdmaDevTab.begin(); rdi != rdmaDevTab.end(); ++rdi)
  {
    int j;
    UInt64 portIf;
    IpAddr portAddr;
    string ifName;
    RdmaDevice *rdevP = *rdi;

    for (p = 1; p <= rdevP->ibAttr.phys_port_cnt; p++)
    {
      fabnum = 0;
      if (!rdmaPortsOpt.empty())
      {
        RdmaPortName rpn(rdevP->rdmaDevName, p, 0);
        set<RdmaPortName>::const_iterator pi = rdmaPortsOpt.find(rpn);
        if (pi == rdmaPortsOpt.end())
          continue;
        fabnum = (*pi).fabnum;
      }
      if (ibv_query_port(rdevP->ibContext, p, &portAttr) != 0)
        Errorm("ibv_query_port failed");
      if (portAttr.state != IBV_PORT_ACTIVE)
      {
        Logt(1, "RDMA port " << rdevP->rdmaDevName << ":" << p
             << " is inactive");
        continue;
      }

      // Fetch the interface ID portion of the GID for the port
      portIf = 0;
      for (j = 0; j < portAttr.gid_tbl_len; j++)
      {
        union ibv_gid gid;
        if (ibv_query_gid(rdevP->ibContext, p, j, &gid) != 0)
          Errorm("ibv_query_gid");

        if (rdevP->ibContext->device->transport_type == IBV_TRANSPORT_IWARP)
            portIf = gid.global.subnet_prefix;
        else
            portIf = gid.global.interface_id;

        if (portIf != 0)
          break;
      }

      // If using CM, find the interface name for this port by matching the
      // port interface ID to the IPv6 link-local address.  Use that to
      // locate a non-link-local IP address.  Skip this port if it doesn't
      // have one.  Since we compare against IPv6 address, this only works
      // if IPv6 support is enabled.  Otherwise, we won't find any ports.
      portAddr.setNone();
      ifName.clear();
      if (useCM)
      {
        for (ni = netInterfaces.begin(); ni != netInterfaces.end(); ++ni)
        {
          if (!ni->addr.isLinkLocal())
            continue;
          if (rdevP->ibContext->device->transport_type == IBV_TRANSPORT_IWARP)
          {
            struct ifreq mac_req;

            if (ioctl_sock < 0)
              ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (ioctl_sock < 0)
              break;

            memset(&mac_req, 0, sizeof mac_req);
            strcpy(mac_req.ifr_name, ni->ifName.c_str());

            if (ioctl(ioctl_sock, SIOCGIFHWADDR, &mac_req) < 0)
            {
               Logm("Cannot get HW address");
               continue;
            }

            if (!(memcmp(&portIf, mac_req.ifr_hwaddr.sa_data, 6)))
            {
              ifName = ni->ifName;
              Logt(3, "Found iWarp RDMA port " << portIfToString(portIf) << " " << ni->ifName);
              break;
            }
          }
          else
          {

#ifdef IPV6_SUPPORT
            struct sockaddr_storage saddr;
            struct sockaddr_in6 *sip6 =
              reinterpret_cast<sockaddr_in6 *>(ni->addr.toSockaddr(0, &saddr));

            // 7 bytes of the port interface ID will match 7 bytes in the
            // IPv6 address.  The first byte won't match because the
            // universal/local bit is flipped in the IPv6 address (see
            // RFC 4291).
            char *a = reinterpret_cast<char *>(&portIf);
            char *b = reinterpret_cast<char *>(&sip6->sin6_addr.s6_addr);
            if (!memcmp(a+1, b+9, 7))
            {
              ifName = ni->ifName;
              break;
            }
#endif
          }
        }

        // Skip this port if no link-local address was found
        if (ifName.empty())
        {
          Logt(1, "RDMA port " << rdevP->rdmaDevName << ":" << p
               << " has no address");
          continue;
        }

        // Now find a non-link-local IP address for this port.  If it
        // has more than one, we'll use the first one that we find.
        for (ni = netInterfaces.begin(); ni != netInterfaces.end(); ++ni)
          if (!ni->addr.isLinkLocal() && ni->ifName == ifName)
          {
            portAddr = ni->addr;
            break;
          }

        // Skip this port if we couldn't find an IP address for it.
        // Without an IP address, other nodes won't be able to connect
        // to it.
        if (portAddr.isNone())
        {
          Logt(1, "RDMA port " << rdevP->rdmaDevName << ":" << p
               << " has no IP address");
          continue;
        }
      }
      rdmaPortTab.push_back(new RdmaPort(rdevP, portIf, portAddr, p, fabnum));
      Logt(1, "using RDMA port " << rdmaPortTab.back()->devString()
           << " " << portIfToString(portIf));
      rdevP->initDev();
    }
  }

  if (rdmaPortTab.empty())
  {
    errmsg = "No RDMA ports found";
    goto exit;
  }

  if (ioctl_sock > 0)
    close(ioctl_sock);

  // Sort ports by fabric number
  sort(rdmaPortTab.begin(), rdmaPortTab.end(), RdmaPort::comp);

  // Start RDMA threads
  if (rdmaAsyncThreadP != NULL)
    Error("rdmaAsync thread already running");
  rdmaAsyncState = tsRun;
  rdmaAsyncThreadP = new RdmaAsync;
  rdmaAsyncThreadP->init();

  if (useCM)
  {
    // Create event channel, which is shared by all devices
    cmChan = rdma_create_event_channel();
    if (cmChan == NULL)
      Errorm("rdma_create_event_channel");

    // Start the connection manager event handler thread
    if (rdmaCMThreadP != NULL)
      Error("rdmaCM thread already running");
    rdmaCMState = tsRun;
    rdmaCMThreadP = new RdmaCM;
    rdmaCMThreadP->init();

    // Listen for connect events using a dummy RdmaConn
    if (cmListenConnP != NULL)
      Error("CM listen already started");
    cmListenConnP = new RdmaConn(NULL, -1);
    cmListenConnP->rdCMListen();
  }

exit:
  rdmaInitialized = true;
  if (!errmsg.empty())
    rdmaShutdown();
  if (devList != NULL)
    ibv_free_device_list(devList);
  return errmsg;
}


// Convert RDMA CM event type to string
string rdmaCMEventToStr(enum rdma_cm_event_type ev)
{
  switch (ev)
  {
    case RDMA_CM_EVENT_ADDR_RESOLVED:   return "ADDR_RESOLVED";
    case RDMA_CM_EVENT_ADDR_ERROR:      return "ADDR_ERROR";
    case RDMA_CM_EVENT_ROUTE_RESOLVED:  return "ROUTE_RESOLVED";
    case RDMA_CM_EVENT_ROUTE_ERROR:     return "ROUTE_ERROR";
    case RDMA_CM_EVENT_CONNECT_REQUEST: return "CONNECT_REQUEST";
    case RDMA_CM_EVENT_CONNECT_RESPONSE:return "CONNECT_RESPONSE";
    case RDMA_CM_EVENT_CONNECT_ERROR:   return "CONNECT_ERROR";
    case RDMA_CM_EVENT_UNREACHABLE:     return "UNREACHABLE";
    case RDMA_CM_EVENT_REJECTED:        return "REJECTED";
    case RDMA_CM_EVENT_ESTABLISHED:     return "ESTABLISHED";
    case RDMA_CM_EVENT_DISCONNECTED:    return "DISCONNECTED";
    case RDMA_CM_EVENT_DEVICE_REMOVAL:  return "DEVICE_REMOVAL";
    case RDMA_CM_EVENT_MULTICAST_JOIN:  return "MULTICAST_JOIN";
    case RDMA_CM_EVENT_MULTICAST_ERROR: return "MULTICAST_ERROR";
    case RDMA_CM_EVENT_ADDR_CHANGE:     return "ADDR_CHANGE";
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:   return "TIMEWAIT_EXIT";
    default:                            return "Unknown";
  }
  return "?";
}


// RDMA connection constructor
RdmaConn::RdmaConn(TcpConn *tconnP, int ndx) :
  cmEventP(NULL), cmWaiting(0), cmBroken(false), cmId(NULL), qp(NULL),
  rkey(0), llid(0), rlid(0), remoteNdx(-1), connP(tconnP), rconnNdx(ndx),
  rdmaPortP(NULL), bytesPending(0)
{
  thInitMutex(&cmMutex);
  thInitCond(&cmCond);
  thInitMutex(&bytesMutex);
}


// RDMA connection destructor
RdmaConn::~RdmaConn()
{
  if (cmId != NULL || qp != NULL)
    Error("RdmaConn deleted while active");
  rdCleanup();
}


// Wait for connection manager to post a connect event for this connection.
rdma_cm_id *RdmaConn::rdWaitForCMConn(const ConnKey *ckeyP,
                                      int *responder_resourcesP,
                                      int *initiator_depthP)
{
  map<ConnKey, rdma_cm_event *>::iterator req;
  rdma_cm_id *newCmid = NULL;
  *responder_resourcesP = *initiator_depthP = 0;

  thLock(&cmMutex);
  cmWaiting++;
  while (true)
  {
    if (cmBroken)
      break;
    req = cmConnRequests.find(*ckeyP);
    if (req != cmConnRequests.end())
    {
      rdma_cm_event *eventP = req->second;
      cmConnRequests.erase(req);

      if (eventP->event != RDMA_CM_EVENT_CONNECT_REQUEST)
        Error("Invalid event in cmConnRequests");

      newCmid = eventP->id;
      *responder_resourcesP = eventP->param.conn.responder_resources;
      *initiator_depthP = eventP->param.conn.initiator_depth;
      rdma_ack_cm_event(eventP);
      break;
    }
    thWait(&cmCond, &cmMutex);
  }
  cmWaiting--;
  if (cmWaiting == 0)
    thBcast(&cmCond);
  thUnlock(&cmMutex);
  return newCmid;
}


// Listen for RDMA connections from connection manager
void RdmaConn::rdCMListen()
{
  if (rdma_create_id(cmChan, &cmId, this, RDMA_PS_TCP) != 0)
    Errorm("rdma_create_id");

  sockaddr_storage saddr;
  IpAddr iaddr;
  iaddr.setAny();
  if (rdma_bind_addr(cmId, iaddr.toSockaddr(0, &saddr)) != 0)
    Errorm("rdma_bind_addr");
  cmPort = ntohs(rdma_get_src_port(cmId));
  if (cmPort == 0)
    Error("cmId not bound to a port");
  Logt(3, "RDMA CM listening on port " << cmPort << ", RdmaConn " << this);
  if (rdma_listen(cmId, 128) != 0)
    Errorm("rdma_listen");
}


// Return RDMA connection info for use in status display
string RdmaConn::rdConnInfo() const
{
  ostringstream os;
  if (rdmaPortP == NULL)
    os << "[none]";
  else
    os << rdmaPortP->devString();
  os << " lid " << llid << "->" << rlid;
  return os.str();
}


// Make an outbound RDMA connection by creating a queue pair and sending a
// message to the other node to tell it to make a matching queue pair.  Use
// the QP information passed back from the server to complete the
// connection.  Return message string if error occurs.
string RdmaConn::rdPrepClient(TcpConn *connP, RdmaPort *rportP,
                              const RdmaPortInfo *destPortInfoP)
{
  ibv_qp_init_attr qpIAttr;
  ibv_qp_attr qpAttr;
  ibv_port_attr portAttr;
  int maxQpRd;
  UInt32 qpnum;
  string errmsg;
  Errno err;
  MsgRecord mr;
  RcvMsg *rmsgP;
  vector<RdmaPort *>::iterator rpi;
  int accFlags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
    IBV_ACCESS_REMOTE_WRITE;
  int e;

  if (useCM)
  {
    if (rdma_create_id(cmChan, &cmId, this, RDMA_PS_TCP) != 0)
      Errorm("rdma_create_id");

    sockaddr_storage saddr, daddr;
    if (rdma_resolve_addr(cmId, rportP->portAddr.toSockaddr(0, &saddr),
                          destPortInfoP->piAddr.toSockaddr(destPortInfoP->piCmPort, &daddr),
                          5000) != 0)
      Errorm("rdma_resolve_addr " << connP->destName() << " "
             << destPortInfoP->toString());

    errmsg = rdCheckCMEvent("rdma_resolve_addr",
                            RDMA_CM_EVENT_ADDR_RESOLVED,
                            RDMA_CM_EVENT_ADDR_ERROR);
    if (errmsg.empty())
    {
      if (rdma_resolve_route(cmId, 5000) != 0)
        Errorm("rdma_resolve_route to " << connP->destName() << " "
               << destPortInfoP->toString());
      errmsg = rdCheckCMEvent("rdma_resolve_route",
                              RDMA_CM_EVENT_ROUTE_RESOLVED,
                              RDMA_CM_EVENT_ROUTE_ERROR);
    }
    if (!errmsg.empty())
    {
      if (rdma_destroy_id(cmId) != 0)
        Errorm("rdma_destroy_id");
      cmId = NULL;
      return errmsg;
    }
    if (cmId->verbs == NULL)
      Error("CM did not create IB context");

    // Locate the RDMA port that was selected for this connection.  We
    // don't need a mutex here because this is the client side, so
    // connections are made sequentially outbound.
    for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
    {
      rdmaPortP = *rpi;
      if (rdmaPortP->pdevP->ibContext == cmId->verbs &&
          rdmaPortP->rdmaPortnum == cmId->port_num)
        break;
    }
    if (rpi == rdmaPortTab.end())
      Error("RDMA port not found for " << connP->destName());
  }
  else
    rdmaPortP = rportP;

  // Set QP attributes
  RdmaDevice *pdevP = rdmaPortP->pdevP;
  pdevP->getQpAttributes(&qpIAttr, pdevP->createCQ(connP->getCnum()));

  maxQpRd = pdevP->ibAttr.max_qp_rd_atom;
  if (maxQpRd == 0)
    maxQpRd = 1;

  if (useCM)
  {
    if (rdma_create_qp(cmId, pdevP->ibPD, &qpIAttr) != 0)
      Errorm("rdma_create_qp");

    rdma_conn_param connParam;
    memset(&connParam, 0, sizeof connParam);

    // Send a unique key in private data to allow the other side to match
    // the incoming RDMA connect request with the correct TCP connection
    // when parallel sockets are being used.
    DataBuff db(sizeof(UInt32) + IpAddr::getSize()*2);
    db.putUInt32(connP->getCnum());
    db.putIpAddr(rportP->portAddr);
    db.putIpAddr(destPortInfoP->piAddr);
    connParam.private_data = db.getBuffP();
    connParam.private_data_len = db.getBufflen();
    connParam.responder_resources = maxQpRd;
    connParam.initiator_depth = maxQpRd;
    connParam.retry_count = 6;
    Logt(2, "RDMA CM connecting from " << rdmaPortP->devString()
         << " to " << destPortInfoP->toString());
    if (rdma_connect(cmId, &connParam) != 0)
      Errorm("rdma_connect " << connP->destName() << " on "
             << rdmaPortP->devString() << " to " << destPortInfoP->toString());

    // Don't wait for our connect request to be accepted yet.  The other
    // side won't look for the connect event until it receives an
    // mtRdmaConn message from us.
    qp = cmId->qp;
  }
  else
  {
    qp = ibv_create_qp(pdevP->ibPD, &qpIAttr);
    if (qp == NULL)
    {
      int e = errno;
      Error("rdPrepClient: ibv_create_qp failed for dest " << connP->destName() << " on device " << rportP->devString() << " " << geterr(e));
    }

    // Change queue pair from RESET to INIT state
    memset(&qpAttr, 0, sizeof(qpAttr));
    qpAttr.qp_state = IBV_QPS_INIT;
    qpAttr.qp_access_flags = accFlags;
    qpAttr.pkey_index = 0;
    qpAttr.port_num = rdmaPortP->rdmaPortnum;

    e = ibv_modify_qp(qp, &qpAttr, IBV_QP_STATE | IBV_QP_ACCESS_FLAGS |
                      IBV_QP_PKEY_INDEX | IBV_QP_PORT);
    if (e)
    {
      Error("rdPrepClient: ibv_modify_qp to INIT failed for dest " << connP->destName() << " on device " << rdmaPortP->devString() << " " << geterr(e));
    }
  }

  maxInline = sinline ? qpIAttr.cap.max_inline_data : 0;
  if (sinline && MSG_HDRSIZE + buffsize > maxInline)
  {
    ostringstream os;
    if (maxInline <= MSG_HDRSIZE)
      os << "max_inline_data value of " << maxInline << " is too small";
    else
      os << "buffsize must be <= " << maxInline - MSG_HDRSIZE
         << " if sinline is on";
    return os.str();
  }

  if (ibv_query_port(pdevP->ibContext, rdmaPortP->rdmaPortnum,
                     &portAttr) != 0)
    Errorm("ibv_query_port failed for " << rdmaPortP->devString());
  llid = portAttr.lid;

  RdmaPortInfo localPinfo(rdmaPortP);
  DataBuff db(5 * sizeof(UInt32) + IpAddr::getSize()*2 + sizeof(Int32) +
              localPinfo.calcPortInfoLen() + destPortInfoP->calcPortInfoLen());
  db.putUInt32(qp->qp_num);
  db.putUInt32(llid);
  db.putUInt32(pdevP->ibMR->rkey);
  db.putUInt32(maxQpRd);
  db.putUInt32(connP->getCnum());
  db.putIpAddr(rdmaPortP->portAddr);
  db.putIpAddr(destPortInfoP->piAddr);
  db.putInt32(rconnNdx);
  localPinfo.putBuff(&db);
  destPortInfoP->putBuff(&db);

  // Tell the server to initialize his side of the connection, and
  // reply with the info that we'll need to connect.  With connection
  // manager, the other side will look for our connect request and
  // accept it.
  err = connP->sendMessage(mtRdmaConn, &db, &mr);
  mr.waitForReplies();
  if (err != E_OK)
    return "RDMA connection failed from " + rdmaPortP->devString()
      + " to " + destPortInfoP->toString();
  rmsgP = mr.nextReply();
  errmsg = rmsgP->errText;
  if (!errmsg.empty())
  {
    delete rmsgP;
    return errmsg;
  }

  // Verify that our connect request was accepted
  if (useCM)
  {
    errmsg = rdCheckCMEvent("rdma_connect", RDMA_CM_EVENT_ESTABLISHED,
                            RDMA_CM_EVENT_REJECTED);
    if (!errmsg.empty())
    {
      if (rdma_destroy_id(cmId) != 0)
        Errorm("rdma_destroy_id");
      cmId = NULL;
      return errmsg;
    }
  }

  // Post some receive requests.  We do this after error conditions are
  // checked so that we won't have outstanding receives if we have to
  // tear down the connection.
  rdPrepPost(connP);

  // Get the remote connection info from the reply and use that to complete
  // the connection.
  qpnum = rmsgP->msgBuff.getUInt32();
  rlid = rmsgP->msgBuff.getUInt32();
  rkey = rmsgP->msgBuff.getUInt32();
  maxQpRd = rmsgP->msgBuff.getUInt32();
  remoteNdx = rmsgP->msgBuff.getInt32();
  remotePinfo.getBuff(&rmsgP->msgBuff);
  delete rmsgP;

  rdConnect(qpnum, maxQpRd, "rdPrepClient");
  Logt(1, "RDMA connected to " << connP->destName());
  Logt(2, "RDMA port " << rdConnInfo() << " to " << remotePinfo.toString());
  return "";
}


// Prepare for completing an inbound RDMA connection by creating a queue
// pair.  We are given the mtRdmaConn message contents, and we return a
// data buffer that can be used as the reply.  Return message string if
// error occurs.
string RdmaConn::rdPrepServer(RcvMsg *rmsgP, TcpConn *connP, DataBuff *dbP)
{
  UInt32 qpnum;
  int maxQpRd, rcnum;
  IpAddr riaddr, rsaddr;
  ibv_qp_init_attr qpIAttr;
  ibv_qp_attr qpAttr;
  ibv_port_attr portAttr;
  RdmaPortInfo desiredPort;
  int responder_resources, initiator_depth;
  string errmsg;
  vector<RdmaPort *>::iterator rpi;
  int accFlags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
    IBV_ACCESS_REMOTE_WRITE;
  int e;

  // Get remote connection info from data passed in the mtRdmaConn message
  qpnum = rmsgP->msgBuff.getUInt32();
  rlid = rmsgP->msgBuff.getUInt32();
  rkey = rmsgP->msgBuff.getUInt32();
  maxQpRd = rmsgP->msgBuff.getUInt32();
  rcnum = rmsgP->msgBuff.getUInt32();
  riaddr = rmsgP->msgBuff.getIpAddr();
  rsaddr = rmsgP->msgBuff.getIpAddr();
  remoteNdx = rmsgP->msgBuff.getInt32();
  remotePinfo.getBuff(&rmsgP->msgBuff);
  desiredPort.getBuff(&rmsgP->msgBuff);

  if (useCM)
  {
    ConnKey ckey(rcnum, riaddr, rsaddr);
    cmId = cmListenConnP->rdWaitForCMConn(&ckey, &responder_resources,
                                          &initiator_depth);
    if (cmId == NULL)
      return "Could not establish RDMA connection from " + connP->destName();
    cmId->context = this;

    // Locate the RDMA port that was used for this connection
    for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
    {
      rdmaPortP = *rpi;
      if (rdmaPortP->pdevP->ibContext == cmId->verbs &&
          rdmaPortP->rdmaPortnum == cmId->port_num)
        break;
    }
    if (rpi == rdmaPortTab.end())
      Error("RDMA port not found for " << connP->destName());
  }
  else
  {
    // Find the RDMA device for the new incoming connection based on the
    // desired port name that the client sent us in the mtRdmaConn message.
    // We should be able to find it because it is one of the names that we
    // sent in the mtParms reply.  We don't need a mutex here because the
    // client at the other end of this TcpConn is making connections
    // serially.
    RdmaPort *rportP = NULL;
    vector<RdmaPort *>::const_iterator rpi;
    for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
    {
      rportP = *rpi;
      if (rportP->pdevP->rdmaDevName == desiredPort.piName &&
          rportP->rdmaPortnum == desiredPort.piPort &&
          rportP->rdmaFabnum == desiredPort.piFabnum)
        break;
    }
    if (rpi == rdmaPortTab.end())
      Error("desired port not found in rdPrepServer");
    rdmaPortP = rportP;
  }

  // Set QP attributes
  RdmaDevice *pdevP = rdmaPortP->pdevP;
  pdevP->getQpAttributes(&qpIAttr, pdevP->createCQ(connP->getCnum()));

  if (useCM)
  {
    if (rdma_create_qp(cmId, pdevP->ibPD, &qpIAttr) != 0)
      Errorm("rdma_create_qp");

    rdma_conn_param connParam;
    memset(&connParam, 0, sizeof connParam);

    if (responder_resources > pdevP->ibAttr.max_qp_rd_atom)
      responder_resources = pdevP->ibAttr.max_qp_rd_atom;
    if (responder_resources == 0)
      responder_resources = 1;
    connParam.responder_resources = responder_resources;

    if (initiator_depth > pdevP->ibAttr.max_qp_init_rd_atom)
      initiator_depth = pdevP->ibAttr.max_qp_init_rd_atom;
    if (initiator_depth == 0)
      initiator_depth = 1;
    connParam.initiator_depth = initiator_depth;

    Logt(3, "RDMA CM accepting connection from " << connP->destName()
         << " on " << rdmaPortP->devString());
    if (rdma_accept(cmId, &connParam) != 0)
      Errorm("rdma_accept");

    errmsg = rdCheckCMEvent("rdma_accept", RDMA_CM_EVENT_ESTABLISHED,
                            RDMA_CM_EVENT_REJECTED);
    if (!errmsg.empty())
    {
      rdma_destroy_qp(cmId);
      if (rdma_destroy_id(cmId) != 0)
        Errorm("rdma_destroy_id");
      cmId = NULL;
      return errmsg;
    }
    qp = cmId->qp;
  }
  else
  {
    qp = ibv_create_qp(pdevP->ibPD, &qpIAttr);
    if (qp == NULL)
    {
      e = errno;
      Error("rdPrepServer: ibv_create_qp failed for dest " << connP->destName() << " on device " << rdmaPortP->devString() << " : " << geterr(e));
    }

    // Change queue pair from RESET to INIT state
    memset(&qpAttr, 0, sizeof(qpAttr));
    qpAttr.qp_state = IBV_QPS_INIT;
    qpAttr.qp_access_flags = accFlags;
    qpAttr.pkey_index = 0;
    qpAttr.port_num = rdmaPortP->rdmaPortnum;

    e = ibv_modify_qp(qp, &qpAttr, IBV_QP_STATE | IBV_QP_ACCESS_FLAGS |
                      IBV_QP_PKEY_INDEX | IBV_QP_PORT);
    if (e)
    {
      Error("rdPrepServer: ibv_modify_qp to INIT failed for dest " << connP->destName() << " on device " << rdmaPortP->devString() << ": " << geterr(e));
    }
  }

  maxInline = sinline ? qpIAttr.cap.max_inline_data : 0;
  if (sinline && MSG_HDRSIZE + buffsize > maxInline)
  {
    ostringstream os;
    if (maxInline <= MSG_HDRSIZE)
      os << "max_inline_data value of " << maxInline << " is too small";
    else
      os << "buffsize must be <= " << maxInline - MSG_HDRSIZE
         << " if sinline is on";
    return os.str();
  }

  if (ibv_query_port(pdevP->ibContext, rdmaPortP->rdmaPortnum,
                     &portAttr) != 0)
    Errorm("ibv_query_port failed for " << rdmaPortP->devString());
  llid = portAttr.lid;

  rdPrepPost(connP);

  // Adjust maxQpRd to be the minimum of the server and client settings.
  // We'll pass back the result for client to use.
  if (maxQpRd > pdevP->ibAttr.max_qp_rd_atom)
    maxQpRd = pdevP->ibAttr.max_qp_rd_atom;
  if (maxQpRd == 0)
    maxQpRd = 1;

  // Ready the connection
  rdConnect(qpnum, maxQpRd, "rdPrepServer");
  Logt(1, "RDMA connection from " << connP->destName());
  Logt(2, "RDMA port " << rdConnInfo() << " from " << remotePinfo.toString());

  // Pass back our info so that the client can complete his side of the
  // connection.
  RdmaPortInfo pinfo(rdmaPortP);
  dbP->newBuff(4 * sizeof(UInt32) + sizeof(Int32) + pinfo.calcPortInfoLen());
  dbP->putUInt32(qp->qp_num);
  dbP->putUInt32(portAttr.lid);
  dbP->putUInt32(pdevP->ibMR->rkey);
  dbP->putUInt32(maxQpRd);
  dbP->putInt32(rconnNdx);
  pinfo.putBuff(dbP);

  return "";
}


// Post receive requests
void RdmaConn::rdPrepPost(TcpConn *connP)
{
  unsigned int n;
  if (useRdma == rAll || useRdma == rInline)
    for (n = 0; n < nTesterThreads; n++)
    {
      PollWait *pwaitP = new PollWait(this);
      pwList.push_back(pwaitP);
      rdPostRecv(pwaitP);
    }
}


// Post a receive work request, reading into the mbuf in the
// PollWait object.
void RdmaConn::rdPostRecv(PollWait *pwaitP)
{
  ibv_sge sge;
  ibv_recv_wr rr;
  ibv_recv_wr *bad_wr = NULL;

  memset(&sge, 0, sizeof(sge));
  sge.addr = reinterpret_cast<UInt64>(pwaitP->mbufP);
  sge.length = mbufSize;
  sge.lkey = rdmaPortP->pdevP->ibMR->lkey;

  memset(&rr, 0, sizeof(rr));
  rr.wr_id = reinterpret_cast<UInt64>(pwaitP);
  rr.next = NULL;
  rr.sg_list = &sge;
  rr.num_sge = 1;

  if (ibv_post_recv(qp, &rr, &bad_wr) != 0)
    Errorm("ibv_post_recv failed for " << rdmaPortP->devString());
  else
    Logt(4, "RDMA read started, pwait " << pwaitP);
}


// Complete an RDMA connection by bringing the queue pair to the ready
// state.  When using connection manager, this work is done by the CM
// library.
void RdmaConn::rdConnect(UInt32 qpnum, UInt32 maxQpRd, const char *whoP)
{
  int e;
  if (useCM)
    return;

  // Change queue pair to RTR state
  ibv_qp_attr qpAttr;
  memset(&qpAttr, 0, sizeof(qpAttr));
  qpAttr.qp_state = IBV_QPS_RTR;
  qpAttr.path_mtu = path_mtu;
  qpAttr.dest_qp_num = qpnum;
  qpAttr.rq_psn = 0;
  qpAttr.max_dest_rd_atomic = maxQpRd;
  qpAttr.min_rnr_timer = 0x12;
  qpAttr.ah_attr.is_global = 0;
  qpAttr.ah_attr.dlid = rlid;
  qpAttr.ah_attr.sl = (unsigned char)serviceLevel;
  qpAttr.ah_attr.src_path_bits = 0;
  qpAttr.ah_attr.port_num = rdmaPortP->rdmaPortnum;

  e = ibv_modify_qp(qp, &qpAttr,
                    IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                    IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                    IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
  if (e)
  {
    Error(whoP << ": ibv_modify_qp to RTR failed for dest " << connP->destName() << " on device " << rdmaPortP->devString() << " " << geterr(e));
  }

  // Change queue pair to RTS state
  memset(&qpAttr, 0, sizeof(qpAttr));
  qpAttr.qp_state = IBV_QPS_RTS;
  qpAttr.timeout = 18;
  qpAttr.retry_cnt = 6;
  qpAttr.rnr_retry = 6,
  qpAttr.sq_psn = 0;
  qpAttr.max_rd_atomic = maxQpRd;

  e = ibv_modify_qp(qp, &qpAttr,
                    IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                    IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                    IBV_QP_MAX_QP_RD_ATOMIC);
  if (e)
  {
    Error(whoP << ": ibv_modify_qp to RTS failed for dest " << connP->destName() << " on device " << rdmaPortP->devString() << " " << geterr(e));
  }
}


// Send RDMA disconnect request to connection manager
void RdmaConn::rdDisconnectCM(string name)
{
  if (cmId == NULL)
    Error("Null cmId in rdDisconnectCM");
  Logt(3, "RDMA CM disconnecting from " << name);
  if (rdma_disconnect(cmId) != 0)
    ; //  This OK to fail with cross-disconnect ?
      //  Errorm("rdma_disconnect");
}


// Tear down RDMA connection.  This does not clean up the pwList.  That has
// to wait until the other side has also been closed so that any posted
// receives will be finished.
void RdmaConn::rdDisconnect()
{
  struct ibv_qp *qpP;
  if (connP != NULL)
    Logt(1, "RDMA disconnect from " << connP->destName()
         << ", " << rdConnInfo());
  if (!useCM)
  {
    qpP = qp;
    qp = NULL;
    if (qpP != NULL)
    {
      int e;
      e = ibv_destroy_qp(qpP);
      if (e != 0)
      {
        string strP = geterr(e);
        printf("rdDisconnect: ibv_destroy_qp for qpP 0x%llX failed with error %d\n",
               qpP, e);
        Error("ibv_destroy_qp failed: " << strP);
      }
    }
    return;
  }
  if (cmId == NULL)
    return;
  if (cmId->qp != NULL)
    rdma_destroy_qp(cmId);
  qp = NULL;

  thLock(&cmMutex);
  if (this == cmListenConnP)
  {
    // The RDMA CM thread might try to add events to the object that we're
    // about to delete, so be sure it is gone.
    if (rdmaCMState == tsRun)
      Error("rdDisconnect called while CM thread running");

    map<ConnKey, rdma_cm_event *>::iterator req;
    for (req = cmConnRequests.begin(); req != cmConnRequests.end(); )
    {
      rdma_ack_cm_event(req->second);
      cmConnRequests.erase(req++);
    }
  }

  // Since we destroyed the QP, we shouldn't be getting any new events, but
  // we could have an old one that hasn't been acknowledged yet.
  if (cmEventP != NULL)
  {
    rdma_ack_cm_event(cmEventP);
    cmEventP = NULL;
  }

  // Release any threads that are still waiting for events
  if (cmWaiting > 0)
  {
    cmBroken = true;
    thBcast(&cmCond);
    while (cmWaiting > 0)
      thWait(&cmCond, &cmMutex);
    cmBroken = false;
  }
  thUnlock(&cmMutex);

  // Destroy CM identifier, now that all events are acknowledged
  if (rdma_destroy_id(cmId) != 0)
    Errorm("rdma_destroy_id");
  cmId = NULL;
}


// Finish cleaning up after RDMA disconnect by deleting any buffers posted
// for receiving.
void RdmaConn::rdCleanup()
{
  while (!pwList.empty())
  {
    delete pwList.front();
    pwList.pop_front();
  }
}


// Write data from test buffer to specified remote address using RDMA
void RdmaConn::rdWrite(DataBuff *testBuffP, RdmaAddr raddr, UInt32 rlen,
                       PollWait *pwaitP)
{
  ibv_sge sge[GlobalVerbs.VerbsMaxSendSge];
  ibv_send_wr sr[max_send_wr];
  ibv_send_wr *bad_wr = NULL;
  enum ibv_wc_status status;
  int nWr;
  int nSge;
  char *srvBuffP;
  char *cliBuffP;
  UInt32 bytesLeft;
  UInt32 bytesThis;

  srvBuffP  = testBuffP->getBuffP();
  cliBuffP  = raddr;
  bytesLeft = rlen;
  bytesThis = rlen;

  Logt(4, "RDMA write len " << rlen << " to " << connP->destName()
       << " rconn " << rconnNdx << " " << rdConnInfo());

  if (rlen != buffsize)
    Error("incorrect length in RDMA write");

  rdAddBytes(rlen);

  while (bytesLeft)
  {
    bytesThis = bytesLeft;
    if (bytesThis > GlobalVerbs.VerbsRdmaMaxSendBytes)
    {
      bytesThis = GlobalVerbs.VerbsRdmaMaxSendBytes;
    }
    nSge = 0;
    sge[nSge].addr   = (uint64_t)srvBuffP;
    sge[nSge].length = bytesThis;
    sge[nSge].lkey   = rdmaPortP->pdevP->ibMR->lkey;

    nWr = 0;
    memset(&sr, 0, sizeof(sr));
    sr[nWr].wr_id      = reinterpret_cast<UInt64>(pwaitP);
    sr[nWr].next       = NULL;
    sr[nWr].sg_list    = &sge[0];
    sr[nWr].num_sge    = 1;
    sr[nWr].opcode     = IBV_WR_RDMA_WRITE;
    sr[nWr].send_flags = IBV_SEND_SIGNALED;
    sr[nWr].wr.rdma.remote_addr = (uint64_t)cliBuffP;
    sr[nWr].wr.rdma.rkey        = rkey;

    pwaitP->srvBuffP = srvBuffP;
    pwaitP->cliBuffP = cliBuffP;
    pwaitP->buffLen  = bytesThis;
    pwaitP->opcode   = IBV_WR_RDMA_WRITE;
    pwaitP->status   = IBV_WC_GENERAL_ERR;
    pwaitP->opId++;

    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdWrite: before post: tid %d opId %llu\n",
             pwaitP->tid, pwaitP->opId);
      thUnlock(&logMutex);
    }
    if (ibv_post_send(qp, &sr[nWr], &bad_wr) != 0)
      Errorm("ibv_post_send failed in rdWrite");
    else
      Logt(4, "RDMA write started, pwait " << pwaitP);
    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdWrite: after post tid %d opId %llu\n",
             pwaitP->tid, pwaitP->opId);
      thUnlock(&logMutex);
    }

    // Wait for RDMA receiver thread to notify us that operation is complete
    status = pwaitP->wait();
    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdRead: after wait tid %d opId %llu status %d\n",
             pwaitP->tid, pwaitP->opId, pwaitP->status);
      thUnlock(&logMutex);
    }
    if (status != IBV_WC_SUCCESS)
    {
      printf("rdWrite: error: tid %d opId %llu status %d %s ibv_wr_opcode %s srvBuffP start 0x%llX end 0x%llX cliBuffP start 0x%llX end 0x%llX len %u\n",
             pwaitP->tid,
             pwaitP->opId,
             status,
             ibv_wc_status_str_nsdperf(status),
             ibv_wr_opcode_str(pwaitP->opcode),
             pwaitP->srvBuffP,
             pwaitP->srvBuffP + pwaitP->buffLen,
             pwaitP->cliBuffP,
             pwaitP->cliBuffP + pwaitP->buffLen,
             pwaitP->buffLen);

      Error("rdWrite: RDMA write on " << rdmaPortP->devString() << " to "
            << remotePinfo.toString() << " failed, status = " << status);
    }
    bytesLeft -= bytesThis;
    srvBuffP  += bytesThis;
    cliBuffP  += bytesThis;
  }
  rdSubBytes(rlen);
}


// Read data from remote address using RDMA into the specified local
// buffer, which must be in registered memory.
void RdmaConn::rdRead(RdmaAddr raddr, UInt32 rlen, char *dataP,
                      PollWait *pwaitP)
{
  ibv_sge sge[GlobalVerbs.VerbsMaxSendSge];
  ibv_send_wr sr[max_send_wr];
  ibv_send_wr *bad_wr = NULL;
  enum ibv_wc_status status;
  int nWr;
  int nSge;
  char *srvBuffP;
  char *cliBuffP;
  UInt32 bytesLeft;
  UInt32 bytesThis;

  srvBuffP  = dataP;
  cliBuffP  = raddr;
  bytesLeft = rlen;

  Logt(4, "RDMA read len " << rlen << " from " << connP->destName()
       << " rconn " << rconnNdx << " " << rdConnInfo());

  if (rlen != buffsize)
    Error("incorect length in RDMA read on " << rdmaPortP->devString());

  rdAddBytes(rlen);

  while (bytesLeft)
  {
    bytesThis = bytesLeft;
    if (bytesThis > GlobalVerbs.VerbsRdmaMaxSendBytes)
    {
      bytesThis = GlobalVerbs.VerbsRdmaMaxSendBytes;
    }
    nSge = 0;
    sge[nSge].addr   = (uint64_t)srvBuffP;
    sge[nSge].length = bytesThis;
    sge[nSge].lkey   = rdmaPortP->pdevP->ibMR->lkey;

    nWr = 0;
    memset(&sr, 0, sizeof(sr));
    sr[nWr].wr_id      = reinterpret_cast<UInt64>(pwaitP);
    sr[nWr].next       = NULL;
    sr[nWr].sg_list    = &sge[0];
    sr[nWr].num_sge    = 1;
    sr[nWr].opcode     = IBV_WR_RDMA_READ;
    sr[nWr].send_flags = IBV_SEND_SIGNALED;
    sr[nWr].wr.rdma.remote_addr = (uint64_t)cliBuffP;
    sr[nWr].wr.rdma.rkey        = rkey;

    pwaitP->srvBuffP = srvBuffP;
    pwaitP->cliBuffP = cliBuffP;
    pwaitP->buffLen  = bytesThis;
    pwaitP->opcode   = IBV_WR_RDMA_READ;
    pwaitP->status   = IBV_WC_GENERAL_ERR;
    pwaitP->opId++;

    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdRead: before post: tid %d opId %llu\n",
             pwaitP->tid, pwaitP->opId);
      thUnlock(&logMutex);
    }
    if (ibv_post_send(qp, &sr[0], &bad_wr) != 0)
      Errorm("ibv_post_send failed in rdRead");
    else
      Logt(4, "RDMA read started, pwait " << pwaitP);
    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdRead: after post tid %d opId %llu\n",
             pwaitP->tid, pwaitP->opId);
      thUnlock(&logMutex);
    }

    // Wait for RDMA receiver thread to notify us that operation is complete
    status = pwaitP->wait();
    if (rdmaDebugLevel > 1)
    {
      thLock(&logMutex);
      printf("rdRead: after wait tid %d opId %llu status %d\n",
             pwaitP->tid, pwaitP->opId, pwaitP->status);
      thUnlock(&logMutex);
    }
    if (status != IBV_WC_SUCCESS)
    {
      printf("rdRead: error: tid %d opId %llu status %d %s ibv_wr_opcode %s srvBuffP start 0x%llX end 0x%llX cliBuffP start 0x%llX end 0x%llX len %u\n",
             pwaitP->tid,
             pwaitP->opId,
             status,
             ibv_wc_status_str_nsdperf(status),
             ibv_wr_opcode_str(pwaitP->opcode),
             pwaitP->srvBuffP,
             pwaitP->srvBuffP + pwaitP->buffLen,
             pwaitP->cliBuffP,
             pwaitP->cliBuffP + pwaitP->buffLen,
             pwaitP->buffLen);
      Error("rdRead: RDMA read on " << rdmaPortP->devString() << " from "
            << remotePinfo.toString() << " failed, status = " << status);
    }

    bytesLeft -= bytesThis;
    srvBuffP  += bytesThis;
    cliBuffP  += bytesThis;
  }

  rdSubBytes(rlen);
}


// Send a message using the RDMA interface.  The data must be in a
// registered memory buffer.  An extra data buffer can be sent using
// auxBuffP in DataBuff.
void RdmaConn::rdSend(DataBuff *dbP, PollWait *pwaitP)
{
  ibv_sge sge[2];
  ibv_send_wr sr;
  ibv_send_wr *bad_wr = NULL;
  enum ibv_wc_status status;
  unsigned int len = dbP->getBufflen() + dbP->getAuxlen();

  if (debugLevel > 3)
  {
    string inl = (len <= maxInline) ? " inline" : "";
    Logt(4, "RDMA send len " << len << inl << " to " << connP->destName()
         << " rconn " << rconnNdx << " " << rdConnInfo());
  }
  rdAddBytes(len);

  memset(&sr, 0, sizeof(sr));
  sr.wr_id = reinterpret_cast<UInt64>(pwaitP);
  sr.next = NULL;
  sr.sg_list = sge;
  sr.num_sge = 1;
  sr.opcode = IBV_WR_SEND;
  sr.send_flags = IBV_SEND_SIGNALED;
  if (len <= maxInline)
    sr.send_flags |= IBV_SEND_INLINE;

  memset(&sge, 0, sizeof(sge));
  sge[0].addr = reinterpret_cast<UInt64>(dbP->getBuffP());
  sge[0].length = dbP->getBufflen();
  sge[0].lkey = rdmaPortP->pdevP->ibMR->lkey;

  if (dbP->getAuxlen() != 0)
  {
    sge[1].addr = reinterpret_cast<UInt64>(dbP->getAuxBuffP());
    sge[1].length = dbP->getAuxlen();
    sge[1].lkey = rdmaPortP->pdevP->ibMR->lkey;
    sr.num_sge = 2;
  }

  if (ibv_post_send(qp, &sr, &bad_wr) != 0)
    Errorm("ibv_post_send failed in rdSend");
  else
    Logt(4, "RDMA send started, pwait " << pwaitP);

  // Wait for RDMA receiver thread to notify us that operation is complete
  status = pwaitP->wait();
  if (status != IBV_WC_SUCCESS)
    Error("RDMA send on " << rdmaPortP->devString() << " to "
          << remotePinfo.toString() << " failed, status = " << status);

  rdSubBytes(len);
}


// Handle an incoming receive completion from the RDMA queue
void RdmaConn::rdRecv(PollWait *pwaitP, unsigned int len)
{
  DataBuff db;
  RcvMsg *rmsgP = new RcvMsg(connP);

  Logt(4, "RDMA recv len " << len << " from " << connP->destName()
       << " rconn " << rconnNdx << " " << rdConnInfo());

  if (len < MSG_HDRSIZE)
    Error("RDMA message too short");

  db.initBuff(pwaitP->mbufP, len);
  if (db.getUInt32() != MSG_MAGIC)
    Error("Invalid message from " << connP->destName());
  rmsgP->msgId   = static_cast<MsgId>(db.getUInt32());
  rmsgP->msgType = static_cast<MType>(db.getUInt32());
  rmsgP->rconnNdx = rconnNdx;
  db.getUInt32(); // Drop unused data length
  rmsgP->timeLine = db.getTimeLine();
  if (len > MSG_HDRSIZE)
  {
    rmsgP->msgBuff.newBuff(len - MSG_HDRSIZE);
    memcpy(rmsgP->msgBuff.getBuffP(), pwaitP->mbufP + MSG_HDRSIZE,
           len - MSG_HDRSIZE);
  }

  // Re-post the receive before dispatching the RcvMsg so that the thread
  // on the other node won't send us another message before we have an
  // mbuf ready to receive it.
  rdPostRecv(pwaitP);
  connP->gotMsg(rmsgP);
}


// Handle an event from the connection manager thread
void RdmaConn::rdHandleCMEvent(rdma_cm_event *eventP)
{
  thLock(&cmMutex);
  if (cmEventP != NULL)
    Error("CM event "<< rdmaCMEventToStr(eventP->event)
          << " received but event pointer was already set");

  // Connect requests come in on the listen socket, and might not have a
  // thread waiting yet (the thread that gets the event is the mtRdmaConn
  // handler).  Store the incoming events in a table, using the unique key
  // sent in the private data.
  if (eventP->event == RDMA_CM_EVENT_CONNECT_REQUEST)
  {
    if (this != cmListenConnP)
      Error("RDMA connect event received on incorrect socket");

    int cnum;
    IpAddr iaddr, saddr;
    DataBuff db(sizeof(UInt32) + iaddr.getSize() + saddr.getSize());
    rdma_conn_param *connParmP = &eventP->param.conn;
    if (connParmP->private_data_len < db.getBufflen())
      Error("Invalid private_data_len in connect request");
    memcpy(db.getBuffP(), connParmP->private_data, db.getBufflen());
    cnum = db.getUInt32();
    iaddr = db.getIpAddr();
    saddr = db.getIpAddr();
    ConnKey ckey(cnum, iaddr, saddr);
    if (cmConnRequests.find(ckey) != cmConnRequests.end())
      Error("duplicate cmConnRequests entry");
    cmConnRequests[ckey] = eventP;
    thBcast(&cmCond);
  }
  else
  {
    cmEventP = eventP;
    thBcast(&cmCond);
  }
  thUnlock(&cmMutex);
}


// Wait for an event from the connection manager and process it.  Return an
// error message if it does not have the expected type.
string RdmaConn::rdCheckCMEvent(const string func,
                                enum rdma_cm_event_type expectedEv,
                                enum rdma_cm_event_type errEv)
{
  ostringstream os;
  thLock(&cmMutex);
  if (cmWaiting > 0)
    Error("More than one thread waiting for CM event");
  cmWaiting++;
  while (cmEventP == NULL && !cmBroken)
    thWait(&cmCond, &cmMutex);
  if (cmEventP != NULL)
  {
    if (cmEventP->event != expectedEv)
    {
      if (cmEventP->event == errEv)
        os << "Error from " << func << ", status " << cmEventP->status
           << ", port " << rdConnInfo();
      else
        os << "Unexpected event from connection manager: "
           << rdmaCMEventToStr(cmEventP->event);
    }
    rdma_ack_cm_event(cmEventP);
    cmEventP = NULL;
  }
  else if (cmBroken)
    os << "RDMA connection broken";
  cmWaiting--;
  thBcast(&cmCond);
  thUnlock(&cmMutex);
  return os.str();
}


// Add to bytes in flight for this connection
void RdmaConn::rdAddBytes(UInt64 nBytes)
{
  if (connP->getNRconns() < 2)
    return;
#ifdef __x86_64
  asm volatile("lock; addq %1,%0"
               : "+m" (bytesPending) : "ri" (nBytes) : "memory", "cc");
#else
  thLock(&bytesMutex);
  bytesPending += nBytes;
  thUnlock(&bytesMutex);
#endif
}


// Subtract from bytes in flight for this connection
void RdmaConn::rdSubBytes(UInt64 nBytes)
{
  if (connP->getNRconns() < 2)
    return;
#ifdef __x86_64
  asm volatile("lock; subq %1,%0"
               : "+m" (bytesPending) : "ri" (nBytes) : "memory", "cc");
#else
  thLock(&bytesMutex);
  bytesPending -= nBytes;
  thUnlock(&bytesMutex);
#endif
}


// PollWait constructor for posting send and receive requests
PollWait::PollWait(RdmaConn *rP)
{
  init();
  mbufP = mbufGet(mbufSize);
  rconnP = rP;
}


// Initialize PollWait object
void PollWait::init()
{
  thInitMutex(&pwMutex);
  thInitCond(&pwCond);
  complete = false;
  status = IBV_WC_SUCCESS;
  mbufP = NULL;
  rconnP = NULL;
  srvBuffP = 0;
  cliBuffP = 0;
  opId = 0;
  buffLen = 0;
  tid = (int)syscall(SYS_gettid);
}


// PollWait Destructor
PollWait::~PollWait()
{
  if (mbufP != NULL)
    mbufFree(mbufP);
}


// Wait for wakeup
ibv_wc_status PollWait::wait()
{
  thLock(&pwMutex);
  while (!complete)
    thWait(&pwCond, &pwMutex);
  complete = false;
  thUnlock(&pwMutex);
  return status;
}


// Wake up waiter
void PollWait::wakeup(ibv_wc_status s)
{
  thLock(&pwMutex);
  status = s;
  complete = true;
  thSignal(&pwCond);
  thUnlock(&pwMutex);
}


// Constructor for RdmaDevice
RdmaDevice::RdmaDevice(ibv_context *ctx) :
  ibContext(ctx), ibCC(NULL), ibPD(NULL), ibMR(NULL), cqSize(0),
  rdmaRcvState(tsRun), rdmaRcvThreadP(NULL)
{
  // Save device name and attributes
  rdmaDevName = ibv_get_device_name(ibContext->device);
  if (ibv_query_device(ibContext, &ibAttr) != 0)
    Errorm("ibv_query_device failed");
}


// Prepare RDMA device for use, if not already done
void RdmaDevice::initDev()
{
  if (ibCC != NULL)
    return;

  // Create a completion channel
  ibCC = ibv_create_comp_channel(ibContext);
  if (ibCC == NULL) Error("ibv_create_comp_channel failed");

  // Allocate protection domain
  ibPD = ibv_alloc_pd(ibContext);
  if (ibPD == NULL) Error("ibv_alloc_pd failed");

  // Register the memory pool, unless it hasn't been created yet
  if (memoryPoolP != NULL)
  {
    int accFlags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
      IBV_ACCESS_REMOTE_WRITE;
    if (rdmaDebugLevel > 0)
    {
      printf("inittDev: memoryPoolBase.addr 0x%llX memoryPoolLen %lld\n",
             memoryPoolBase.addr,
             memoryPoolLen);
    }
    ibMR = ibv_reg_mr(ibPD, memoryPoolBase, memoryPoolLen, accFlags);
    if (ibMR == NULL) Errorm("ibv_reg_mr failed");
  }
  else
    ibMR = NULL;

  // Determine the completion queue size.  Reduce it if it exceeds the
  // device limit.
  do
  {
    cqSize = 2 * (nTesterThreads * nClients + nWorkers * max_send_wr);
    if (cqSize <= ibAttr.max_cqe)
      break;
    max_send_wr--;
  }
  while (max_send_wr > 0);

  if (max_send_wr <= 0)
  {
    cout << "cqSize = 2 * (nTesterThreads * nClients + nWorkers * 32) = "
              << 2 * (nTesterThreads * nClients + nWorkers * MAX_RDMA_SEND_WR)
              << "exceeds max_cqe" << ibAttr.max_cqe
         << "reduce one of "
         << "nTesterThreads " << nTesterThreads
         << "nClients " << nClients
         << "nWorkers " << nWorkers << endl;
    Error("ibv_create_cq cqeSize exceeded");
  }

  // Start an RDMA receiver thread for this device
  rdmaRcvState = tsRun;
  rdmaRcvThreadP = new RdmaReceiver(this);
  rdmaRcvThreadP->init();
}


// Create a completion queue for this device, if not already done for
// another parallel RDMA connection.
ibv_cq *RdmaDevice::createCQ(int cnum)
{
  map<int, ibv_cq *>::iterator cqi = cqtab.find(cnum);
  if (cqi != cqtab.end())
    return cqi->second;
  ibv_cq *cq = ibv_create_cq(ibContext, cqSize, NULL, ibCC, 0);
  if (cq == NULL) Error("ibv_create_cq failed");
  cqtab[cnum] = cq;

  // Request completion notifications
  if (ibv_req_notify_cq(cq, 0) != 0)
    Errorm("ibv_req_notify_cq failed");
  return cq;
}


// Destroy all completion queues used by this device
void RdmaDevice::destroyCQ()
{
  map<int, ibv_cq *>::iterator cqi;
  for (cqi = cqtab.begin(); cqi != cqtab.end(); )
  {
    int e = ibv_destroy_cq(cqi->second);
    if (e != 0)
      Error("ibv_destroy_cq failed: " << geterr(e));
    cqtab.erase(cqi++);
  }
}


// Fill in initial QP attributes for a new connection
void RdmaDevice::getQpAttributes(ibv_qp_init_attr *qpIAttrP, ibv_cq *cq) const
{
  // Calculate the size of the work request queues.  Since RDMA writes are
  // initiated by tester threads sending from or reading into client nodes,
  // the total number of outstanding messages will never exceed the number
  // of testers times number of clients.  In addition to these messages,
  // worker threads could also be sending replies.  Double that number to
  // allow for the case where the RDMA receiver thread is handling a send
  // event (i.e. isn't actively polling), and wakes a tester or worker, who
  // then proceeds to send again before a new poll can be started,
  // overflowing the send queue.  If we make the queue big enough to allow
  // for all of these requests, it should never overflow.  The alternative
  // would be to manage the queuing ourselves, to limit the maximum number
  // of sends that are outstanding at one time.
  //
  // Make the receive queue the same size as the send queue.  That way
  // every send will be guaranteed to have a corresponding receive queue
  // entry available.
  int maxWr = (nTesterThreads * nClients + nWorkers) * 2;

  // Cut back the size if it exceeds the device limit
  if (maxWr > ibAttr.max_qp_wr)
    maxWr = ibAttr.max_qp_wr;

  // Fill in QP attributes
  memset(qpIAttrP, 0, sizeof(ibv_qp_init_attr));
  qpIAttrP->send_cq = cq;
  qpIAttrP->recv_cq = cq;
  qpIAttrP->sq_sig_all = 1;
  qpIAttrP->qp_type = IBV_QPT_RC;
  qpIAttrP->cap.max_send_wr = maxWr;
  qpIAttrP->cap.max_recv_wr =
    (useRdma == rAll || useRdma == rInline) ? maxWr : 1;
  if (GlobalVerbs.VerbsMaxSendSge > ibAttr.max_sge)
    GlobalVerbs.VerbsMaxSendSge = ibAttr.max_sge;
  qpIAttrP->cap.max_send_sge = GlobalVerbs.VerbsMaxSendSge;
  qpIAttrP->cap.max_recv_sge = (useRdma == rInline) ? 2 : 1;
  qpIAttrP->cap.max_inline_data = sinline ? 128 : 0;
}


// Convert device name to a string for messages
string RdmaPort::devString() const
{
  ostringstream os;
  os << pdevP->rdmaDevName << ":" << rdmaPortnum;
  if (rdmaFabnum != 0)
    os << ":" << rdmaFabnum;
  if (!portAddr.isNone())
    os << " " << portAddr.toString();
  if (portIf != 0)
    os << " " << portIfToString(portIf);
  return os.str();
}
#else /* else not RDMA */

// Non-RDMA versions
static char *poolGet(unsigned int len) { return new char[len]; }
static void poolFree(char *buffP) { delete [] buffP; }
#endif // RDMA


// Wrapper for thread body
extern "C" void *thread_wrapper(void *argP)
{
  int rc;
  Thread *thP = static_cast<Thread *>(argP);
  thP->startup();
  rc = thP->threadBody();

  // Tell the main thread to clean us up
  thLock(&globalMutex);
  deadThreads.push_back(thP);
  thBcast(&globalCond);
  thUnlock(&globalMutex);
  pthread_exit(&rc);
  return NULL;
}


// Start the thread and wait for it to get going (it would be nice to do
// this from the constructor, except that virtual functions always use the
// base class version, so we wouldn't be able to call the thread body
// routine).
void Thread::init()
{
  thLock(&globalMutex);
  running = false;
  nThreadsStarted++;
  if (pthread_create(&th, NULL, thread_wrapper, this) != 0)
    Errorm("pthread_create");
  while (!running)
    thWait(&globalCond, &globalMutex);
  thUnlock(&globalMutex);
}


// Call this routine when a new thread starts to tell the init routine
// that the thread is running.
void Thread::startup()
{
  thLock(&globalMutex);
  running = true;
  thBcast(&globalCond);
  thUnlock(&globalMutex);
}


// Clean up threads if they exit, and return when all threads are gone
void waitForThreads()
{
  thLock(&globalMutex);
  while (nThreadsStarted > 0)
  {
    while (deadThreads.empty())
      thWait(&globalCond, &globalMutex);

    Thread *thP = deadThreads.front();
    deadThreads.pop_front();
    thUnlock(&globalMutex);

    thJoin(thP->getThread(), NULL);
    delete thP;

    thLock(&globalMutex);
    nThreadsStarted--;
  }
  thUnlock(&globalMutex);
}


// Receiver constructor
Receiver::Receiver()
{
  thInitMutex(&receiverMutex);
  thInitCond(&receiverCond);

  // Create a socket pair to be used for waking up receiver thread when it
  // is in poll.
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, rcvSocks) < 0)
    Errorm("socketpair");
  setSockNonblocking(rcvSocks[0]);
  setSockNonblocking(rcvSocks[1]);
}


// Receiver destructor
Receiver::~Receiver()
{
  int j;
  for (j = 0; j < 2; j++)
    if (close(rcvSocks[j]) < 0)
      Errorm("close rcvSocks");
}


// Receiver thread body
int Receiver::threadBody()
{
  int j, numfd, nFDs = 0;
  TcpConn *connP;
  bool isSockpair;
  map<Sock, TcpConn *> socketTab;
  map<Sock, TcpConn *>::iterator siter;
#ifdef USE_EPOLL
  int epollFd;
  epoll_event ev, events[MAX_POLLFD_NUM];
#else
  Sock socket = INVALID_SOCK;
  PollSock fdList[MAX_POLLFD_NUM];
  bool fdNeedsRefresh = false;
#endif

  thLock(&globalMutex);
  nReceiversRunning++;
  thUnlock(&globalMutex);

#ifdef USE_EPOLL
  epollFd = epoll_create(MAX_POLLFD_NUM);
  if (epollFd < 0)
    Errorm("epoll_create failed");

  ev.events = EPOLLIN | EPOLLET;
  ev.data.ptr = NULL;
  if (epoll_ctl(epollFd, EPOLL_CTL_ADD, rcvSocks[0], &ev) < 0)
    Errorm("epoll_ctl EPOLL_CTL_ADD rcvSocks");
  nFDs++;
#endif

  while (true)
  {
    // Wait for the listen thread to give us a socket
    thLock(&receiverMutex);
    while (newSockets.empty() && receiverRun)
      thWait(&receiverCond, &receiverMutex);
    thUnlock(&receiverMutex);
    if (!receiverRun)
      break;

    // Loop, polling the sockets
    while (receiverRun)
    {
      // If the ListenAccept thread passed us any new sockets, add them
      // to table of sockets that we poll.
      thLock(&receiverMutex);
      while (!newSockets.empty())
      {
        NewSock ns = newSockets.front();
        newSockets.pop_front();
        if (socketTab.find(ns.sock) != socketTab.end())
          Error("socket " << ns.sock << " is already in socketTab");
        socketTab[ns.sock] = ns.connP;
#ifdef USE_EPOLL
        thUnlock(&receiverMutex);
        ev.events = EPOLLIN | EPOLLET;
        ev.data.ptr = ns.connP;
        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, ns.sock, &ev) < 0)
          Errorm("epoll_ctl EPOLL_CTL_ADD");
        nFDs++;

        // Handle any events that might have come in before the socket was
        // registered to epoll.
        if (ns.connP->receiverEvent() != E_OK)
        {
          socketTab.erase(ns.sock);
          if (epoll_ctl(epollFd, EPOLL_CTL_DEL, ns.sock, NULL) < 0)
            Errorm("epoll_ctl EPOLL_CTL_DEL");
          nFDs--;
          ns.connP->connShutdown();
          ns.connP->releaseConn();
        }
        thLock(&receiverMutex);
#else
        fdNeedsRefresh = true;
#endif
      }
      thUnlock(&receiverMutex);

#ifdef USE_EPOLL
      if (nFDs == 0)
        break;
#else
      // Rebuild poll array if socket table has changed
      if (fdNeedsRefresh)
      {
        if (socketTab.empty())
          break;
        memset(fdList, 0, sizeof(fdList));
        fdList[0].fd = rcvSocks[0];
        fdList[0].events = POLLIN;
        fdList[0].revents = 0;
        nFDs = 1;
        for (siter = socketTab.begin();
             siter != socketTab.end();
             ++siter, nFDs++)
        {
          if (nFDs >= MAX_POLLFD_NUM)
            Error("more than " << MAX_POLLFD_NUM << " connections per receiver");
          fdList[nFDs].fd = siter->first;
          fdList[nFDs].events = POLLIN;
          fdList[nFDs].revents = 0;
        }
        fdNeedsRefresh = false;
      }
#endif

      // Wait for data from a socket
      while (receiverRun)
      {
#ifdef USE_EPOLL
        numfd = epoll_wait(epollFd, events, MAX_POLLFD_NUM, 5 * 1000);
#else
        numfd = poll(fdList, nFDs, 5 * 1000);
#endif
        if (numfd >= 0)
          break;
        if (errno != EINTR)
          Errorm("poll");
      }
      if (!receiverRun)
        break;

      for (j = 0; j < nFDs && numfd > 0; j++)
      {
#ifdef USE_EPOLL
        connP = reinterpret_cast<TcpConn *>(events[j].data.ptr);
        isSockpair = (connP == NULL);
#else
        if (fdList[j].revents == 0)
          continue;
        socket = fdList[j].fd;
        isSockpair = (socket == rcvSocks[0]);
#endif
        numfd--;

        // If this is the socket pair, that means someone sent us a wakeup
        // notification.  Remove all data from the socket.
        if (isSockpair)
        {
          char tmpBuf[16];
          while (recv(rcvSocks[0], tmpBuf, sizeof(tmpBuf), 0) > 0);
          continue;
        }

#ifndef USE_EPOLL
        siter = socketTab.find(socket);
        if (siter == socketTab.end())
          Error("socket " << socket << " not found in socketTab");
        connP = siter->second;
#endif

        // Handle event from socket
        if (connP->receiverEvent() == E_OK)
          continue;

        // Error occurred on receive, so delete socket from table and shut
        // it down.
        socketTab.erase(connP->getSock());
#ifdef USE_EPOLL
        if (epoll_ctl(epollFd, EPOLL_CTL_DEL, connP->getSock(), NULL) < 0)
          Errorm("epoll_ctl EPOLL_CTL_DEL");
        nFDs--;
#else
        fdNeedsRefresh = true;
#endif
        connP->receiveDone();
      }
    }
  }
#ifdef USE_EPOLL
  if (close(epollFd) < 0)
    Errorm("close epollFd");
#endif
  for (siter = socketTab.begin(); siter != socketTab.end(); ++siter)
    siter->second->receiveDone();

  thLock(&globalMutex);
  nReceiversRunning--;
  if (nReceiversRunning == 0)
    thBcast(&globalCond);
  thUnlock(&globalMutex);

  return 0;
}


// Add a new TCP connection for this receiver to handle
void Receiver::addConn(Sock sock, TcpConn *connP)
{
  connP->holdConn();
  thLock(&receiverMutex);
  newSockets.push_back(NewSock(sock, connP));
  thSignal(&receiverCond);
  thUnlock(&receiverMutex);
  wakeUp();
}


// Wake up receiver thread if it is in poll
void Receiver::wakeUp()
{
  int rc;
  char buf[1] = {'x'};
  while (true)
  {
    rc = send(rcvSocks[1], buf, 1, 0);
    if (rc == 0)
      Error("rcvSocks disconnected");
    if (rc > 0 || errno == EAGAIN || errno == EWOULDBLOCK)
      break;
    if (errno != EINTR)
      Errorm("send to rcvSocks");
  }
}


// Nudge the thread
void Receiver::nudge()
{
  thLock(&receiverMutex);
  thKill(getThread(), SIGUSR1);
  thBcast(&receiverCond);
  thUnlock(&receiverMutex);
}


// Stop the receiver threads
static void shutReceivers()
{
  vector<Receiver *>::iterator r;
  thLock(&globalMutex);
  receiverRun = false;
  for (r = receiverTab.begin(); r != receiverTab.end(); ++r)
    (*r)->nudge();
  while (nReceiversRunning > 0)
    thWait(&globalCond, &globalMutex);
  receiverTab.clear();
  thUnlock(&globalMutex);
}


// Perform round-robin selection of receiver threads
static Receiver *pickReceiver()
{
  Receiver *rcvP;
  thLock(&globalMutex);
  rcvP = *nextReceiver;
  if (++nextReceiver == receiverTab.end())
    nextReceiver = receiverTab.begin();
  thUnlock(&globalMutex);
  return rcvP;
}


// InuseWaiter constructor
InuseWaiter::InuseWaiter(MType tmt, MsgId tmsgId, unsigned int tdatalen)
{
  thInitCond(&iwCond);
  mt = tmt;
  msgId = tmsgId;
  datalen = tdatalen;
}


// Assign priority according to message type.  Messages with high-valued
// types will be granted use of the socket for sending before lower ones.
// Inbound messages with priority less than 5 are considered bulk messages,
// and will be processed after all other message types.
static int msgPriority(MType mt)
{
  int j;
  static int mpri[mtLast];
  static bool inited = false;

  if (mt <= 0 || mt >= mtLast)
    Error("Invalid message type");
  if (!inited)
  {
    // Set up message priority table for faster lookups
    for (j = 0; j < mtLast; j++)
      switch (j)
      {
        case mtKill:      mpri[j] = 9; break;
        case mtStatOn:    mpri[j] = 8; break;
        case mtStatOff:   mpri[j] = 8; break;
        case mtWrite:     mpri[j] = 1; break;
        case mtRead:      mpri[j] = 1; break;
        case mtNwrite:    mpri[j] = 1; break;
        case mtGetdata:   mpri[j] = 1; break;
        case mtRdmaWrite: mpri[j] = 2; break;
        default:          mpri[j] = 5; break;
      }
    inited = true;
  }
  return mpri[mt];
}


// Convert message type to string for debug output
static string mtToString(MType mt)
{
  switch (mt)
  {
    case mtUnknown:         return "Unknown";
    case mtReply:           return "Reply";
    case mtReplyErr:        return "ReplyErr";
    case mtVersion:         return "Version";
    case mtWrite:           return "Write";
    case mtRead:            return "Read";
    case mtNwrite:          return "Nwrite";
    case mtGetdata:         return "Getdata";
    case mtKill:            return "Kill";
    case mtConnect:         return "Connect";
    case mtReset:           return "Reset";
    case mtRdmaDone:        return "RdmaDone";
    case mtRdmaConn:        return "RdmaConn";
    case mtRdmaGetBuffs:    return "RdmaGetBuffs";
    case mtRdmaDisconnCM:   return "RdmaDisconnCM";
    case mtRdmaDisconn:     return "RdmaDisconn";
    case mtRdmaCleanup:     return "RdmaCleanup";
    case mtRdmaWrite:       return "RdmaWrite";
    case mtParms:           return "Parms";
    case mtAlloc:           return "Alloc";
    case mtFree:            return "Free";
    case mtTest:            return "Test";
    case mtStatus:          return "Status";
    case mtStatOn:          return "StatOn";
    case mtStatOff:         return "StatOff";
    case mtIdlePct:         return "IdlePct";
    default:                break;
  }
  return "??";
}


// Compare two InuseWaiter entries to determine which has higher priority
bool InuseCmp::operator()(const InuseWaiter *w1P, const InuseWaiter *w2P) const
{
  // High priority messages go first
  int p1 = msgPriority(w1P->mt);
  int p2 = msgPriority(w2P->mt);
  if (p1 < p2) return true;
  if (p1 > p2) return false;

  // Short messages go ahead of long ones, but if they are close in size,
  // consider them to be the same.
  p1 = w1P->datalen / 1000;
  p2 = w2P->datalen / 1000;
  if (p1 < p2) return true;
  if (p1 > p2) return false;

  // Older messages go ahead of later ones
  return w1P->msgId < w2P->msgId;
}


// TcpConn constructor
TcpConn::TcpConn(Sock tsock, IpAddr tdest)
{
  thInitMutex(&connMutex);
  thInitCond(&connCond);
  refCount = 0;
  tcSock = tsock;
  dest = tdest;
  inuse = false;
  broken = false;
  thLock(&globalMutex);
  cnum = nextCnum++;
  thUnlock(&globalMutex);
#ifdef RDMA
  lastConnNdx = 0;
  nRconns = 0;
#endif
  recvState = rcv_idle;
  recvP = NULL;
  recvlen = 0;
  recvmax = 0;
  recvMsgP = NULL;
}


// TcpConn destructor
TcpConn::~TcpConn()
{
  delete recvMsgP;
}


// Assign a unique message ID
MsgId TcpConn::assignMsgId()
{
  MsgId n;
#ifdef __x86_64
  n = 1;
  asm volatile("lock; xaddl %0,%1"
               : "+r" (n), "+m" (nextMsgId) : : "memory", "cc");
#else
  thLock(&globalMutex);
  n = nextMsgId++;
  thUnlock(&globalMutex);
#endif
  return n;
}


// Convert destination host name to string for messages
string TcpConn::destName() const
{
  ostringstream os;
  os << dest.toString() << "/" << cnum;
  return os.str();
}


// Put a hold on this TcpConn so that it won't be deleted
void TcpConn::holdConn()
{
#ifdef __x86_64
  int n = 1;
  asm volatile("lock; xaddl %0,%1"
               : "+r" (n), "+m" (refCount) : : "memory", "cc");
  Logt(5, "holdConn " << n+1 << ", sock " << tcSock);
#else
  thLock(&connMutex);
  refCount++;
  Logt(5, "holdConn " << refCount << ", sock " << tcSock);
  thUnlock(&connMutex);
#endif
}


// Release hold on this TcpConn and delete it if count is zero.  This is
// the only place that the socket is closed.
void TcpConn::releaseConn()
{
#ifdef __x86_64
  int n = -1;
  asm volatile("lock; xaddl %0,%1"
               : "+r" (n), "+m" (refCount) : : "memory", "cc");
  Logt(5, "releaseConn " << n-1 << ", sock " << tcSock);
  if (n > 1)
    return;
  if (!broken)
    Error("TcpConn released while still connected");
#else
  thLock(&connMutex);
  refCount--;
  Logt(5, "releaseConn " << refCount << ", sock " << tcSock);
  if (refCount > 0)
  {
    thUnlock(&connMutex);
    return;
  }
  if (!broken)
    Error("TcpConn released while still connected");
  thUnlock(&connMutex);
#endif

  if (close(tcSock) < 0)
    Errorm("socket close");
  Logt(1, "Closed connection to " << destName());

#ifdef RDMA
  while (nRconns > 0)
  {
    delete rconnTab.back();
    rconnTab.pop_back();
    nRconns--;
  }
#endif
  delete this;
}


// Shut down the TCP connection.  Everyone who is using the connection
// should wake up due to the socket shutdown and release their hold.  When
// the hold count goes to zero, the socket will be closed and the TcpConn
// deleted.  The broken flag ensures that only one thread calls shutdown
// and prevents new threads from starting to use the connection.
void TcpConn::connShutdown()
{
  thLock(&connMutex);
  if (!broken)
  {
    if (shutdown(tcSock, SHUT_RDWR) < 0 && errno != ENOTCONN)
      Errorm("socket shutdown");
    broken = true;

    // Wake up anyone who was waiting for exclusive use of the socket.
    // Wait for them to notice the broken connection and pop themselves off
    // the waiters list.
    while (!waiters.empty())
    {
      thSignal(&waiters.top()->iwCond);
      thWait(&connCond, &connMutex);
    }

#ifdef RDMA
    // Tear down any RDMA connection
    rdmaDisconnect();
#endif
  }
  thUnlock(&connMutex);

  // Remove any queued messages for this connection.  If a worker thread
  // already picked up the RcvMsg, then he should fail quickly since the
  // broken flag is set.
  thLock(&workerMutex);
  list<RcvMsg *>::iterator riter;
  list<RcvMsg *> *qP = &msgQueue;
  riter = qP->begin();
  while (true)
  {
    if (riter == qP->end())
    {
      if (qP != &msgQueue)
        break;
      qP = &bulkQueue;
      riter = qP->begin();
      continue;
    }

    RcvMsg *rmsgP = *riter;
    if (rmsgP->connP != this)
      ++riter;
    else
    {
      riter = qP->erase(riter);
      delete rmsgP;
    }
  }
  thUnlock(&workerMutex);

  // Scan the pending reply table and wake up anybody who is waiting for a
  // reply on this connection.
  int b;
  for (b = 0; b < nRtBuckets; b++)
  {
    ReplyEntry *reP, *nextP, *prevP = NULL;
    thLock(&pendReplyTab[b].bucketMutex);
    for (reP = pendReplyTab[b].bucketHeadP; reP != NULL; reP = nextP)
    {
      nextP = reP->reNextP;
      if (reP->connP != this)
      {
        prevP = reP;
        continue;
      }
      if (prevP == NULL)
        pendReplyTab[b].bucketHeadP = nextP;
      else
        prevP->reNextP = nextP;

      // Manufacture a dummy RcvMsg with errText set and use that to wake
      // up sender.
      RcvMsg *rmsgP = new RcvMsg(this);
      rmsgP->msgId = reP->msgId;
      rmsgP->errText = "connection broken";
      reP->mrP->gotReply(rmsgP);

      reP->reNextP = pendReplyTab[b].freeListP;
      pendReplyTab[b].freeListP = reP;
    }
    thUnlock(&pendReplyTab[b].bucketMutex);
  }
}


// Call this to clean up connection when a receiver thread is done with it.
// This will clear any partially-received message, which is necessary for
// the TcpConn object to be deleted, since RcvMsg keeps a hold.
void TcpConn::receiveDone()
{
  connShutdown();
  delete recvMsgP;
  recvMsgP = NULL;
  releaseConn();
}


// Handle an event from poll
Errno TcpConn::receiverEvent()
{
  Errno err = E_OK;
  DataBuff db;

  Logt(4, "event on sock " << tcSock << " " << destName());

  // Keep reading until the socket blocks or is shut down due to an error
  while (true)
  {
    if (broken)
    {
      err = E_BROKEN;
      break;
    }

    switch (recvState)
    {
      case rcv_idle:
        recvMsgP = new RcvMsg(this);
        recvP = recvMsgP->hdr;
        recvmax = MSG_HDRSIZE;
        recvState = rcv_header;
        break;

      case rcv_header:
        err = recvMessage();
        if (err != E_OK)
          break;

        // Message header format:
        //    UInt32 magic      Magic number, should be MSG_MAGIC
        //    UInt32 msgId      Message identifier
        //    UInt32 msgType    Message type
        //    UInt32 msgLen     Length of data which follows this header
        //    TimeLine timeLine Time line record to calculate network delay of each message

        db.initBuff(recvMsgP->hdr, MSG_HDRSIZE);
        if (db.getUInt32() != MSG_MAGIC)
        {
          Log("Invalid message from " << destName());
          err = E_BADMSG;
          break;
        }
        recvMsgP->msgId   = static_cast<MsgId>(db.getUInt32());
        recvMsgP->msgType = static_cast<MType>(db.getUInt32());
        recvmax           = db.getUInt32();
        recvMsgP->timeLine = db.getTimeLine();

        if (recvmax > 16 * 1024 * 1024)
          Error("Invalid msgLen");

        if (recvmax > 0)
        {
          recvMsgP->msgBuff.newBuff(recvmax);
          recvP = recvMsgP->msgBuffP();
        }
        recvState = rcv_data;
        break;

      case rcv_data:
        err = recvMessage();
        if (err != E_OK)
          break;

        gotMsg(recvMsgP);
        recvMsgP = NULL;
        recvState = rcv_idle;
        break;

      default:
        Error("invalid receiver state");
    }
    if (err == E_WOULDBLOCK)
      return E_OK;
    if (err != E_OK)
      break;
  }
  if (err != E_OK)
  {
    // Discard any partially received message
    delete recvMsgP;
    recvMsgP = NULL;
  }
  return err;
}


// Call this just after a message has been receieved, from either the
// TCP receiver or the RDMA receiver thread.
void TcpConn::gotMsg(RcvMsg *rmsgP)
{
  if (debugLevel > 3 || (debugLevel > 0 &&
                         msgPriority(rmsgP->msgType) > 4 &&
                         rmsgP->msgType != mtReply))
  {
    ostringstream os;
    os << "got msg " << mtToString(rmsgP->msgType)
       << " ID " << rmsgP->msgId << " len " << rmsgP->msgLen()
       << " from " << destName();
    if (rmsgP->rconnNdx >= 0)
      os << " rconn " << rmsgP->rconnNdx;
    Logt(1, os.str());
  }

  // If this is a reply, wake up the sender.  Otherwise, pass the
  // received message to a worker thread.
  if (rmsgP->msgType == mtReply || rmsgP->msgType == mtReplyErr)
  {
    rmsgP->timeLine->replyRecvStamp = getStamp();
    MsgRecord *mrP = getReply(rmsgP->msgId, true);

    // If this is an error reply, pull out the error text
    if (rmsgP->msgType == mtReplyErr)
      rmsgP->errText = rmsgP->msgBuff.getString();

    mrP->gotReply(rmsgP);
  }
  else
  {
    rmsgP->timeLine->msgRecvStamp = getStamp();
    thLock(&workerMutex);
    if (msgPriority(rmsgP->msgType) < 5)
      bulkQueue.push_back(rmsgP);
    else
      msgQueue.push_back(rmsgP);
    thSignal(&workerCond);
    thUnlock(&workerMutex);
  }
}


// Find the test buffer address used in an Nwrite message
void TcpConn::getSourceAddr(MsgId msgId, char **srcAddrPP,
                            unsigned int *srcLenP)
{
  MsgRecord *mrP = getReply(msgId, false);
  if (mrP == NULL)
    Error("pending message not found for Getdata request");
  *srcAddrPP = mrP->srcAddrP;
  *srcLenP = mrP->srcLen;
}


// This routine is called from a receiver thread to read pending data.
// Data is read into the buffer pointed to by recvP until recvmax bytes
// have been read.  The recvlen variable is used to keep track of how much
// has been read so far.  Returns E_WOULDBLOCK if more data is needed from
// socket.
Errno TcpConn::recvMessage()
{
  while (recvlen < recvmax)
  {
    int rc = recv(tcSock, recvP, recvmax - recvlen, 0);
    if (rc == 0)
    {
      Log("Connection to " << destName() << " broken");
      return E_CONNRESET;
    }
    if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      Logm("Receive from " << destName() << " failed");
      return E_CONNRESET;
    }
    if (rc < 0)
      return E_WOULDBLOCK;

    Logt(4, "received " << rc << " bytes from " << destName());
    recvlen += rc;
    recvP += rc;
  }
  recvlen = 0;
  recvmax = 0;
  recvP = NULL;
  return E_OK;
}


// Send a message on this connection.  When a reply is received, it will be
// added to the reply list in mrP.  Caller must call waitForReplies before
// deleting the MsgRecord.
Errno TcpConn::sendMessage(MType mt, DataBuff *dbP, MsgRecord *mrP,
                           PollWait *pwaitP, TimeLine *timeLine)
{
  return sendit(mt, mt, 0, dbP, mrP, pwaitP, timeLine);
}


// Internal routine used by sendMessage and sendReply to send a message
Errno TcpConn::sendit(MType mt, MType origmt, MsgId msgId, DataBuff *mdbP,
                      MsgRecord *mrP, PollWait *pwaitP, TimeLine *timeLine)
{
  union { char hdr[MSG_HDRSIZE]; UInt64 n; } h; // Make it double-word aligned
  DataBuff db;
  msghdr msg;
  iovec iov[2];
  int rc, iovCount;
  unsigned int skipBytes;
  PollSock ps;
  bool doRdma;
  char *dataP = NULL;
  unsigned int datalen = 0;

  if (mdbP != NULL)
  {
    dataP = mdbP->getBuffP();
    datalen = mdbP->getBufflen();
  }

  // If rdma setting is "all" or "inline", then send this message using the
  // RDMA interface rather than the TCP socket.  Only do this for message
  // types that are used in testing, not for administrative or setup
  // messages.
  doRdma = (useRdma == rAll || useRdma == rInline) &&
    (origmt == mtWrite || origmt == mtRead || origmt == mtNwrite ||
     origmt == mtGetdata || origmt == mtRdmaWrite);

  // Assign a unique message ID for this message
  if (msgId == 0)
    msgId = assignMsgId();

  // Wait for exclusive use of the socket for sending
  if (!doRdma)
  {
    thLock(&connMutex);
    if (inuse)
    {
      InuseWaiter iw(origmt, msgId, datalen);
      waiters.push(&iw);
      while ((inuse && !broken) || waiters.top() != &iw)
        thWait(&iw.iwCond, &connMutex);
      waiters.pop();
      if (broken)
        thSignal(&connCond);
    }
    if (broken)
    {
      thUnlock(&connMutex);
      return E_BROKEN;
    }
    inuse = true;
    thUnlock(&connMutex);
  }

  if (mt != mtReply && mt != mtReplyErr)
  {
    // Record this message ID in the MsgRecord for caller to wait on.  We
    // must do this before adding an entry in pendReplyTab because a socket
    // break will scan pendReplyTab and attempt to remove the entry for
    // this ID from the MsgRecord.
    mrP->addMsg(msgId);

    // Add an entry to pending reply table, which will be used to wake the
    // MsgRecord when the reply comes in.  It will also be used to locate
    // waiters if the connection breaks.
    addReply(msgId, mrP, this);
    timeLine->msgSendStamp = getStamp();
  }
  else
  {
    timeLine->replySendStamp = getStamp();
  }

  if (debugLevel > 3 || (debugLevel > 0 && mt != mtReply &&
                         msgPriority(mt) > 4))
  {
    ostringstream os;
    os << "sending msg " << mtToString(mt) << " ID " << msgId
       << " len " << datalen << " to " << destName();
    Logt(1, os.str());
  }

  // Build message header.  If doing RDMA, put it in a registered message
  // buffer.  For inline RDMA, an extra buffer full of data may be sent in
  // the auxBuff, so pass that directly to rdmaSend in an auxBuff instead
  // of copying it.
  if (doRdma)
  {
    if (MSG_HDRSIZE + datalen > mbufSize)
      Error("RDMA message too big");

    // For RDMA messages, caller must supply a PollWait object with
    // a message buffer.
    if (pwaitP == NULL || pwaitP->mbufP == NULL)
      Error("PollWait missing in sendit");

    db.initBuff(pwaitP->mbufP, MSG_HDRSIZE + datalen);
    if (useRdma == rInline && mdbP != NULL)
      db.setAux(mdbP->getAuxBuffP(), mdbP->getAuxlen());
  }
  else
    db.initBuff(h.hdr, MSG_HDRSIZE);



  db.putUInt32(MSG_MAGIC);
  db.putUInt32(msgId);
  db.putUInt32(mt);
  db.putUInt32(datalen + db.getAuxlen());
  db.putTimeLine(timeLine);

#ifdef RDMA
  if (doRdma)
  {
    if (datalen > 0)
      memcpy(pwaitP->mbufP + MSG_HDRSIZE, dataP, datalen);
    rdmaSend(&db, pwaitP);
    return E_OK;
  }
#endif

  // Combine header and data into an iovec
  iov[0].iov_base = h.hdr;
  iov[0].iov_len = MSG_HDRSIZE;
  if (datalen == 0)
    iovCount = 1;
  else
  {
    iov[1].iov_base = dataP;
    iov[1].iov_len = datalen;
    iovCount = 2;
  }

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = iovCount;
  skipBytes = 0;

  // Send the header and data
  while (msg.msg_iovlen > 0)
  {
    if (broken)
      break;

    if (skipBytes > 0)
    {
      while (msg.msg_iovlen > 0 && skipBytes >= msg.msg_iov[0].iov_len)
      {
        skipBytes -= msg.msg_iov[0].iov_len;
        msg.msg_iov++;
        msg.msg_iovlen--;
      }
      if (skipBytes == 0)
        continue;
      msg.msg_iov[0].iov_base =
        static_cast<char *>(msg.msg_iov[0].iov_base) + skipBytes;
      msg.msg_iov[0].iov_len -= skipBytes;
      skipBytes = 0;
      continue;
    }

    rc = sendmsg(tcSock, &msg, SENDMSG_FLAGS);
    if (rc == 0)
    {
      Warn("connection to " << destName() << " broken");
      connShutdown();
      break;
    }
    if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      Warnm("send to " << destName() << " failed");
      connShutdown();
      break;
    }
    if (rc > 0)
    {
      skipBytes = rc;
      Logt(4, "write " << rc << " bytes on sock " << tcSock
           << " " << destName());
      continue;
    }

    // Socket is blocked on send, so poll and try again
    ps.fd = tcSock;
    ps.events = POLLOUT;
    ps.revents = 0;
    while (true)
    {
      rc = poll(&ps, 1, 1000);
      if (rc >= 0)
        break;
      if (errno != EINTR)
        Errorm("poll for send");
    }
    skipBytes = 0;
  }

  // Release exclusive use of the socket
  thLock(&connMutex);
  inuse = false;
  if (!waiters.empty())
    thSignal(&waiters.top()->iwCond);
  thUnlock(&connMutex);
  return broken ? E_BROKEN : E_OK;
}


// Count how many ports in a set match the given fabric number
static int portsInFabric(const set<RdmaPortInfo> *portsP, int fabnum)
{
  int n = 0;
  set<RdmaPortInfo>::const_iterator pi;
  for (pi = portsP->begin(); pi != portsP->end(); ++pi)
    if (pi->piFabnum == fabnum)
      n++;
  return n;
}


#ifdef RDMA
// Initiate an RDMA connections to the server node on the other end of this
// TCP connection.  This is called only on client nodes.  If more than one
// RDMA device is present (either on server side, client side, or both),
// then multiple connections will be made.
string TcpConn::rdmaClientConnect(const set<RdmaPortInfo> *remotePortsP)
{
  RdmaConn *rconnP;
  string errmsg;
  int nConn = 0, n, m;
  MsgRecord mr;
  RcvMsg *rmsgP;
  Errno err;
  vector<RdmaPort *>::const_iterator rpi, rpi2;
  set<RdmaPortInfo>::const_iterator pi;
  vector<const RdmaPortInfo *> sortedPorts;
  vector<const RdmaPortInfo *>::const_iterator spi;

  if (nRconns != 0)
    Error("RDMA already connected");
  if (remotePortsP->empty())
    Error("no remote RDMA ports in client connect");

  // Sort the remote ports by fabric number.  The local ports in
  // rdmaPortTab are already sorted.
  sortedPorts.reserve(remotePortsP->size());
  for (pi = remotePortsP->begin(); pi != remotePortsP->end(); ++pi)
    sortedPorts.push_back(&(*pi));
  sort(sortedPorts.begin(), sortedPorts.end(), RdmaPortInfo::comp);

  if (rdmaPortTab.empty())
    Error("no RDMA ports in client connect");

  spi = sortedPorts.begin();
  for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
  {
    RdmaPort *rportP = *rpi;

    // If the number of ports matches, make connections one to one.
    // Otherwise connect n to m.
    n = portsInFabric(remotePortsP, rportP->rdmaFabnum);
    if (n == 0)
      continue;
    m = 0;
    for (rpi2 = rdmaPortTab.begin(); rpi2 != rdmaPortTab.end(); ++rpi2)
      if ((*rpi2)->rdmaFabnum == rportP->rdmaFabnum)
        m++;
    if (n == m)
      n = 1;
    else
      spi = sortedPorts.begin();

    for (; n > 0; n--)
    {
      rconnP = new RdmaConn(this, nRconns);
      rconnTab.push_back(rconnP);
      nRconns++;

      // Pick the next destination port with matching fabric from the list
      // of remote port names.  We shouldn't run out because we calculated
      // the number of matching ports above.
      while (spi != sortedPorts.end() && (*spi)->piFabnum != rportP->rdmaFabnum)
        ++spi;
      if (spi == sortedPorts.end())
        Error("ran out of remote ports");
      const RdmaPortInfo *destPinfoP = *spi;
      ++spi;

      // Create a queue pair and put the connection info into a message
      // buffer to pass to the server.  If using connection manager, send a
      // connect request here, but don't wait for it to be accepted yet.
      errmsg = rconnP->rdPrepClient(this, rportP, destPinfoP);
      if (!errmsg.empty())
        goto exit;

      nConn++;
      if (nConn >= maxRdma)
        goto connComplete;
    }
  }

connComplete:
  if (nRconns == 0)
    errmsg = "No matching ports found for RDMA connection";

  // Get remote RDMA memory buffers for use in write tests
  if (errmsg.empty())
  {
    err = sendMessage(mtRdmaGetBuffs, NULL, &mr);
    mr.waitForReplies();
    if (err != E_OK)
    {
      rmsgP = NULL;
      errmsg = "Send to " + destName() + " failed";
    }
    else
    {
      rmsgP = mr.nextReply();
      errmsg = rmsgP->errText;
    }
    if (errmsg.empty())
      for (n = rmsgP->msgBuff.getUInt32(); n > 0; n--)
        remoteBuffs.push_back(rmsgP->msgBuff.getUInt64());
    delete rmsgP;
  }

exit:
  // If connection failed for any device, tear down all connections
  if (!errmsg.empty())
  {
    while (nRconns > 0)
    {
      rconnTab.back()->rdDisconnect();
      delete rconnTab.back();
      rconnTab.pop_back();
      nRconns--;
    }
  }
  return errmsg;
}


// Establish an RDMA connection on the server side in response to an
// mtRdmaConn message from client.  The client node has already created a
// queue pair, and passes us the necessary connection info in the
// mtRdmaConn message.  We will set up our own queue pair and reply with
// our connection info, and then the client will use that to complete the
// connection.
void TcpConn::rdmaServerConnect(RcvMsg *rmsgP)
{
  string errmsg;
  DataBuff db;

  // Prepare connection.  With connection manager, this will wait until a
  // connection event is received.
  RdmaConn *rconnP = new RdmaConn(this, nRconns);
  errmsg = rconnP->rdPrepServer(rmsgP, this, &db);
  if (!errmsg.empty())
  {
    rmsgP->sendReply(NULL, errmsg);
    delete rconnP;
    return;
  }

  // Connection is complete, so save it in connection table
  rconnTab.push_back(rconnP);
  nRconns++;

  rmsgP->sendReply(&db);
}


// Tell connection manager to disconnect from this node
void TcpConn::rdmaSendCMDiscReq()
{
  if (!useCM || nRconns == 0)
    return;

  DataBuff db(sizeof(Int32));
  MsgRecord mr;

  // Send disconnect request.  The other side will get a disconnect event,
  // although no thread is waiting for it yet.
  vector<RdmaConn *>::iterator rci;
  for (rci = rconnTab.begin(); rci != rconnTab.end(); ++rci)
  {
    (*rci)->rdDisconnectCM(destName());

    // Tell the other side to disconnect us.  This will verify that he got
    // the disconnect event, and also generate a disconnect event on our
    // side.  If we waited long enough, we'd see the event eventually, but
    // having the other side disconnect makes it happen much quicker.
    db.resetBuff();
    db.putInt32((*rci)->rdGetRemoteNdx());
    if (sendMessage(mtRdmaDisconnCM, &db, &mr) != E_OK)
      Log("Send to " << destName() << " failed");
    else
      mr.checkReplies();

    // Verify that the disconnect is complete
    (*rci)->rdCheckCMEvent("rdma_disconnect", RDMA_CM_EVENT_DISCONNECTED,
                           RDMA_CM_EVENT_TIMEWAIT_EXIT);
  }
}


// Process a request from other side to disconnect using connection
// manager.
void TcpConn::rdmaRecvCMDiscReq(RcvMsg *rmsgP)
{
  if (!useCM || nRconns == 0)
    return;

  Int32 ndx = rmsgP->msgBuff.getInt32();
  if (ndx < 0 || ndx >= nRconns)
    Error("Invalid RdmaConn index in rdmaRecvCMDiscReq");
  RdmaConn *rconnP = rconnTab[ndx];

  // The other side has disconnected, so we should see an event.  The
  // event probably arrived before we were called.
  rconnP->rdCheckCMEvent("rdma_disconnect", RDMA_CM_EVENT_DISCONNECTED,
                         RDMA_CM_EVENT_TIMEWAIT_EXIT);
  rconnP->rdDisconnectCM(destName());
}


// Tear down RDMA connection
void TcpConn::rdmaDisconnect()
{
  vector<RdmaConn *>::iterator rci;
  for (rci = rconnTab.begin(); rci != rconnTab.end(); ++rci)
    (*rci)->rdDisconnect();
}


// Finish cleaning up after RDMA disconnect
void TcpConn::rdmaCleanup()
{
  if (nRconns == 0)
    return;
  remoteBuffs.clear();
  while (!givenBuffs.empty())
  {
    poolFree(givenBuffs.front());
    givenBuffs.pop_front();
  }
  while (nRconns > 0)
  {
    rconnTab.back()->rdCleanup();
    delete rconnTab.back();
    rconnTab.pop_back();
    nRconns--;
  }
}


// Write data from test buffer to specified remote address using RDMA
void TcpConn::rdmaWrite(DataBuff *testBuffP, RdmaAddr raddr, UInt32 rlen,
                        PollWait *pwaitP)
{
  if (raddr == 0)
    Error("RDMA write with no buffer address");
  if (nRconns == 0)
    Error("RDMA write with no RDMA connection");
  chooseRconnP()->rdWrite(testBuffP, raddr, rlen, pwaitP);
}


// Read data from remote address using RDMA into the specified local buffer
void TcpConn::rdmaRead(RdmaAddr raddr, UInt32 rlen, char *dataP,
                       PollWait *pwaitP)
{
  if (raddr == 0)
    Error("RDMA read with no buffer address");
  if (nRconns == 0)
    Error("RDMA read with no RDMA connection");
  chooseRconnP()->rdRead(raddr, rlen, dataP, pwaitP);
}


// Send a message using the RDMA interface
void TcpConn::rdmaSend(DataBuff *dbP, PollWait *pwaitP)
{
  if (nRconns == 0)
    Error("RDMA write with no RDMA connection");
  chooseRconnP()->rdSend(dbP, pwaitP);
}


// Allocate an RDMA buffer from the pool on remote node
RdmaAddr TcpConn::getRemoteBuff()
{
  RdmaAddr rBuff;
  thLock(&connMutex);
  if (remoteBuffs.empty())
    Error("remote buffer pool exhausted");
  rBuff = remoteBuffs.front();
  remoteBuffs.pop_front();
  thUnlock(&connMutex);
  return rBuff;
}


// Return a remote RDMA buffer to the pool
void TcpConn::freeRemoteBuff(RdmaAddr rBuff)
{
  thLock(&connMutex);
  remoteBuffs.push_back(rBuff);
  thUnlock(&connMutex);
}


// Choose which RDMA connection to use
RdmaConn *TcpConn::chooseRconnP()
{
  if (nRconns < 1)
    Error("No RDMA connections available");
  if (nRconns == 1)
    return rconnTab[0];

  int j, ndx = 0, penalty;
  UInt64 pending, minPending = ULLONG_MAX;
  for (j = 0; j < nRconns; j++)
  {
    // If this connection was used last time, give it a penalty.  This is
    // all done without mutex protection since it doesn't matter much if
    // the choice is wrong.
    penalty = (j == lastConnNdx) ? 100 : 0;
    pending = rconnTab[j]->rdGetBytesPending() + penalty;
    if (pending < minPending)
    {
      minPending = pending;
      ndx = j;
    }
  }
  lastConnNdx = ndx;
  return rconnTab[ndx];
}
#endif // RDMA


// Target destructor
Target::~Target()
{
  if (connP != NULL)
  {
    connP->connShutdown();
    connP->releaseConn();
  }
}


// Create a TCP connection to target node.  Return error message if failure.
string Target::makeConnection()
{
  string errmsg, ver;
  Sock sock;
  int rc;
  RcvMsg *rmsgP;

  if (connP != NULL)
    return errmsg;

  if ((sock = socket(iaddr.getFamily(), SOCK_STREAM, 0)) == INVALID_SOCK)
    Errorm("socket open");
  setSockSizes(sock);

  // Don't delay sending messages
  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
    Errorm("setsockopt TCP_NODELAY");

  // Make the connection
  sockaddr_storage saddr;
  rc = connect(sock, iaddr.toSockaddr(port, &saddr), iaddr.getSocklen());
  if (rc < 0)
  {
    errmsg = geterr(errno);
    close(sock);
    return errmsg;
  }

  // Set for non-blocking IO
  setSockNonblocking(sock);

  connP = new TcpConn(sock, iaddr);
  connP->holdConn();
  pickReceiver()->addConn(sock, connP);
  rmsgP = sendm(mtVersion);
  if (!rmsgP->errText.empty())
  {
    errmsg = rmsgP->errText;
    delete rmsgP;
    return errmsg;
  }

  // Verify that his version matches ours
  ver = rmsgP->msgBuff.getString();
  delete rmsgP;
  if (ver != version)
    return "Version mismatch.  Remote version is \"" + ver + "\".";

  Log("Connected to " << hostname);
  return errmsg;
}


// Calculate the number of RDMA connections between two nodes, given the
// set of RDMA ports on each node.  Connection are only made between ports
// with matching fabric numbers.
static int calcNConns(const set<RdmaPortInfo> *p1, const set<RdmaPortInfo> *p2)
{
  int n = 0, n1, n2;
  set<RdmaPortInfo>::const_iterator pi;

  for (pi = p1->begin(); pi != p1->end(); ++pi)
  {
    n1 = portsInFabric(p1, pi->piFabnum);
    n2 = portsInFabric(p2, pi->piFabnum);

    // If the number of ports matches, make connections one to one.
    // Otherwise connect n to m.
    n += (n1 == n2) ? 1 : n2;
  }
  if (n > maxRdma)
    n = maxRdma;
  n *= nParallel;
  return n;
}


// Calculate how many RDMA connections are going to be made on this target
int Target::calcConnectionCount() const
{
  if (useRdma == rOff)
    return 0;
  int n = 0;
  map<IpAddr, Target *>::const_iterator node;
  for (node = allNodes.begin(); node != allNodes.end(); ++node)
  {
    Target *targP = node->second;
    if (targP->isClient == isClient)
      continue;
    n += calcNConns(&remPinfo, &targP->remPinfo);
  }
  return n;
}


// Send one message, wait for reply, and return it.  If an error occurs,
// put error message in errText.
RcvMsg *Target::sendm(MType mt, DataBuff *dbP, PollWait *pwaitP,
                      char *srcAddrP, unsigned int srcLen, TimeLine *timeLine)
{
  Errno err;
  MsgRecord mr(srcAddrP, srcLen);
  err = connP->sendMessage(mt, dbP, &mr, pwaitP, timeLine);
  mr.waitForReplies();
  if (err != E_OK)
  {
    RcvMsg *rmsgP = new RcvMsg(connP);
    rmsgP->errText = "connection to " + name() + " broken";
    return rmsgP;
  }
  return mr.nextReply();
}


// Convert host name and IP address to printable name for error messages
string Target::name() const
{
  return hostString(hostname, iaddr);
}


// MsgRecord constructor
MsgRecord::MsgRecord(char *tsrcAddrP, unsigned int tsrcLen)
{
  thInitMutex(&waitMutex);
  thInitCond(&waitCond);
  srcAddrP = tsrcAddrP;
  srcLen = tsrcLen;
}


// MsgRecord destructor
MsgRecord::~MsgRecord()
{
  thLock(&waitMutex);
  if (!waitTab.empty())
    Error("MsgRecord destructor called with messages pending");

  // Delete any replies
  while (!replies.empty())
  {
    delete replies.front();
    replies.pop_front();
  }
  thUnlock(&waitMutex);
}


// Add an entry to set of waiting messages
void MsgRecord::addMsg(MsgId msgId)
{
  thLock(&waitMutex);
  if (!waitTab.insert(msgId).second)
    Error("message " << msgId << " is already in waitTab");
  thUnlock(&waitMutex);
}


// Wait for replies from all messages to be received
void MsgRecord::waitForReplies()
{
  thLock(&waitMutex);
  while (!waitTab.empty())
    thWait(&waitCond, &waitMutex);
  thUnlock(&waitMutex);
}


// Wait for any outstanding replies, check all received replies for errors,
// printing a message if found, and then delete the replies.  Return true
// if an error was seen.
bool MsgRecord::checkReplies()
{
  RcvMsg *rmsgP;
  bool gotError = false;
  waitForReplies();
  for (rmsgP = nextReply(); rmsgP != NULL; rmsgP = nextReply())
  {
    if (rmsgP->showError()) gotError = true;
    delete rmsgP;
  }
  return gotError;
}


// Call this when a reply is received
void MsgRecord::gotReply(RcvMsg *rmsgP)
{
  thLock(&waitMutex);
  if (waitTab.erase(rmsgP->msgId) != 1)
    Error("msgId not found in waitTab");
  replies.push_back(rmsgP);
  if (waitTab.empty())
    thSignal(&waitCond);
  thUnlock(&waitMutex);
}


// Return the next reply, and remove it from reply list
RcvMsg *MsgRecord::nextReply()
{
  RcvMsg *rmsgP = NULL;
  thLock(&waitMutex);
  if (!replies.empty())
  {
    rmsgP = replies.front();
    replies.pop_front();
  }
  thUnlock(&waitMutex);
  return rmsgP;
}


// Add a new entry to histogram.  Input should be a response time in HTime
// units (nanoseconds).
void Histogram::addEntry(HTime t)
{
  if (t < 0)
    return;

  nEvents++;
  totalTime += t;

#ifdef LOG_HIST
  // Round to two significant digits to cut down the number of buckets.
  // This doesn't work very well, and requires changes to the plotting
  // code, so it is under ifdef for now.
  t = llrint(siground(t, 2));
#else
  // Round time to nearest millisecond to reduce the histogram size
  t = httomsec(t) * 1000000LL;
#endif

  map<HTime, UInt32>::iterator b = buckets.find(t);
  if (b == buckets.end())
    buckets[t] = 1;
  else
    b->second++;
}


// Add in the contents of another histogram
void Histogram::addHist(const Histogram *hP)
{
  map<HTime, UInt32>::const_iterator hiter;
  map<HTime, UInt32>::iterator b;
  for (hiter = hP->buckets.begin(); hiter != hP->buckets.end(); ++hiter)
  {
    b = buckets.find(hiter->first);
    if (b == buckets.end())
      buckets[hiter->first] = hiter->second;
    else
      b->second += hiter->second;
  }
  nEvents += hP->nEvents;
  totalTime += hP->totalTime;
}


// Print a histogram
ostream &operator<<(ostream &os, const Histogram &h)
{
  h.printHist(os);
  return os;
}


// Print a histogram
void Histogram::printHist(ostream &os) const
{
  int oldwidth;
  map<HTime, UInt32>::const_iterator b;

  if (nEvents == 0)
    return;

  oldwidth = os.width();
  for (b = buckets.begin(); b != buckets.end(); ++b)
    os << "  " << setw(7) << siground(httosec(b->first)*1000.0, 4)
       << "  " << setw(7) << b->second << endl;
  os.width(oldwidth);
}


// Return average value in histogram in seconds
double Histogram::average() const
{ return httosec(totalTime) / nEvents; }


// Return median value in histogram in seconds
double Histogram::median() const
{
  int n = 0;
  HTime retval = 0;
  map<HTime, UInt32>::const_iterator b;
  for (b = buckets.begin(); b != buckets.end(); ++b)
  {
    n += b->second;
    if (n >= nEvents/2)
    {
      retval = b->first;
      break;
    }
  }
  return httosec(retval);
}


double Histogram::standardDeviation() const
{
  double variance = 0;
  double avg = httosec(totalTime) / nEvents;
  map<HTime, UInt32>::const_iterator b;
  for (b = buckets.begin(); b != buckets.end(); ++b)
  {
    double diff = httosec(b->first) - avg;
    variance += diff * diff * b->second;
  }
  return sqrt(variance / nEvents);
}


// Return minimum time value in histogram in seconds
double Histogram::minTime() const
{ return buckets.empty() ? 0 : httosec(buckets.begin()->first); }


// Return maximum time value in histogram in seconds
double Histogram::maxTime() const
{ return buckets.empty() ? 0 : httosec(buckets.rbegin()->first); }


// Return maximum bucket value in this histogram
UInt32 Histogram::maxBucket() const
{
  if (buckets.empty())
    return 0;
  return max_element(buckets.begin(), buckets.end(), BucketCmp())->second;
}


// Send a reply to a message with data from the specified DataBuff.  If the
// DataBuff pointer is NULL, then send an empty reply.  If errText is not
// empty then send an error reply (mtReplyErr) with that text.
void RcvMsg::sendReply(DataBuff *dbP, string errText, PollWait *pwaitP)
{
  if (timeLine == NULL)
  {
    timeLine = new TimeLine();
  }
  if (!errText.empty())
  {
    msgBuff.newBuff(calcLen(errText));
    msgBuff.putString(errText);
    connP->sendit(mtReplyErr, msgType, msgId, &msgBuff, NULL, pwaitP, timeLine);
  }
  else
    connP->sendit(mtReply, msgType, msgId, dbP, NULL, pwaitP, timeLine);
}


// If an error occurred on this reply, print a message and return true
bool RcvMsg::showError()
{
  if (errText.empty())
    return false;
  Log("Error reply from " << connP->destName() << ": " << errText);
  return true;
}


// Start handling a request from the admin node.  If another request is
// already being handled, send back an error reply and return true.  The
// admin node should never send a new request before the previous one has
// finished.  This routine is to catch the case of multiple admin nodes, or
// an admin node restart.
bool RcvMsg::startAdminReq()
{
  if (!server)
    Error("admin request received from " << connP->destName());
  thLock(&globalMutex);
  if (cmdInProgress)
  {
    thUnlock(&globalMutex);
    sendReply(NULL, "command already in progress");
    return true;
  }
  cmdInProgress = true;
  thUnlock(&globalMutex);
  return false;
}


// Stop handling an admin command request
void RcvMsg::endAdminReq()
{
  thLock(&globalMutex);
  cmdInProgress = false;
  thUnlock(&globalMutex);
}


// Message handler for mtVersion
//    Input:
//       None
//    Returns:
//       String version
void RcvMsg::handleVersion()
{
  msgBuff.newBuff(calcLen(version));
  msgBuff.putString(version);
  sendReply(&msgBuff);
}


// Message handler for mtKill
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleKill()
{
  pthread_t laThread = laThreadP->getThread();
  sendReply(NULL);
  connP->connShutdown();
  shutReceivers();

  // Set quit flag and wake up all threads so that they'll notice it
  // and exit.  When they are all gone, the main thread will exit.
  quitflag = true;

  thLock(&testerMutex);
  nTesterThreads = 0;
  thBcast(&testerCond);
  thUnlock(&testerMutex);

  thKill(laThread, SIGUSR1);

  thLock(&workerMutex);
  thBcast(&workerCond);
  thUnlock(&workerMutex);

  multimap<IpAddr, Target *>::iterator node;
  for (node = serverNodes.begin(); node != serverNodes.end(); )
  {
    delete node->second;
    serverNodes.erase(node++);
  }
#ifdef RDMA
  rdmaKillThreads();
#endif
}


// Message handler for mtWrite
//    Input:
//       char[buffsize]   Test data buffer
//    Returns:
//       UInt64    seed value found in test data (only used if verify is on)
void RcvMsg::handleWrite(MsgWorker *mwP)
{
  UInt64 seed = 0;
  if (msgBuff.getBufflen() >= sizeof(UInt64))
    seed = msgBuff.getUInt64();
  if (verify && !msgBuff.verifyBuff(seed))
    Error("Data verification failed");
  msgBuff.newBuff(sizeof(UInt64));
  msgBuff.putUInt64(seed);
  sendReply(&msgBuff, errText, &mwP->pwait);
}


// Message handler for mtRdmaWrite
//    Input:
//       RdmaAddr  RDMA buffer address where data was written
//       UInt32    buffsize
//    Returns:
//       UInt64    seed value found in test data (only used if verify is on)
void RcvMsg::handleRdmaWrite(MsgWorker *mwP)
{
#ifdef RDMA
  RdmaAddr raddr = msgBuff.getRdmaAddr();
  UInt32 rlen = msgBuff.getUInt32();
  DataBuff db(raddr, rlen);
  UInt64 seed = 0;

  // Be sure that the address passed is within our memory pool
  if (raddr.addr < memoryPoolBase.addr ||
      raddr.addr + rlen >
      memoryPoolBase.addr + static_cast<Int64>(poolBuffsize) * poolCount)
    Error("buffer address out of range in RdmaWrite");

  if (db.getBufflen() >= sizeof(UInt64))
    seed = db.getUInt64();
  if (verify && !db.verifyBuff(seed))
    Error("Data verification failed");
  msgBuff.newBuff(sizeof(UInt64));
  msgBuff.putUInt64(seed);
  sendReply(&msgBuff, errText, &mwP->pwait);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtNwrite
//    Input:
//       RdmaAddr  RDMA buffer address (not used if RDMA is off)
//       UInt32    buffsize
//    Returns:
//       UInt64    seed value found in test data (only used if verify is on)
void RcvMsg::handleNwrite(MsgWorker *mwP)
{
  string errText;
  DataBuff db;
  UInt64 seed = 0;

  // This is an NSD-style write request.  If RDMA is enabled, read directly
  // from the other node's test data buffer into this worker thread's
  // dedicated memory buffer.  Otherwise send a Getdata RPC to fetch the
  // data.
#ifdef RDMA
  if (useRdma != rOff)
  {
    RdmaAddr raddr = msgBuff.getRdmaAddr();
    UInt32 rlen = msgBuff.getUInt32();
    if (mwP->rdBuffP == NULL || mwP->rdLen != buffsize)
      Error("bad RDMA buffer in handleNwrite");
    if (rlen != mwP->rdLen)
      Error("incorrect buffer size in handleNwrite");
    timeLine->rdStartStamp = getStamp();
    connP->rdmaRead(raddr, rlen, mwP->rdBuffP, &mwP->pwait);
    timeLine->rdFinStamp = getStamp();
    db.initBuff(mwP->rdBuffP, mwP->rdLen);
    if (db.getBufflen() >= sizeof(UInt64))
      seed = db.getUInt64();
    if (verify && !db.verifyBuff(seed))
      Error("Data verification failed");
  }
  else
#endif
  {
    MsgRecord mr;
    msgBuff.newBuff(sizeof(UInt32));
    msgBuff.putUInt32(msgId);
    Errno err = connP->sendMessage(mtGetdata, &msgBuff, &mr, &mwP->pwait, new TimeLine());
    mr.waitForReplies();
    if (err != E_OK)
      errText = "send failed";
    else
    {
      RcvMsg *replyP = mr.nextReply();
      errText = replyP->errText;
      if (errText.empty())
      {
        if (replyP->msgBuff.getBufflen() > sizeof(UInt64))
          seed = replyP->msgBuff.getUInt64();
        if (verify && !replyP->msgBuff.verifyBuff(seed))
          Error("Data verification failed");
      }
      // Add the network delay of getData cycle to timeLine->msgRecvStamp,
      // so final network delay will include getData cycle network delay.
      timeLine->msgRecvStamp += replyP->timeLine->getNetworkDelay();
      delete replyP;
    }
  }
  msgBuff.newBuff(sizeof(UInt64));
  msgBuff.putUInt64(seed);
  sendReply(&msgBuff, errText, &mwP->pwait);
}


// Message handler for mtGetdata
//    Input:
//       UInt32    MsgId of the Nwrite message
//    Returns:
//       char[buffsize]   Test data buffer
void RcvMsg::handleGetdata(MsgWorker *mwP)
{
  // Use the MsgId to find the MsgRecord of the original Nwrite message.
  // That will have the buffer address of the test buffer that we should
  // send.
  MsgId msgId = msgBuff.getUInt32();
  char *srcAddrP;
  unsigned int srcLen;
  connP->getSourceAddr(msgId, &srcAddrP, &srcLen);
  if (srcAddrP == NULL || srcLen == 0)
    Error("source address missing in Getdata request");
  msgBuff.initBuff(srcAddrP, srcLen);
  sendReply(&msgBuff, "", NULL);
}


// Message handler for mtRead
//    Input:
//       UInt64    seed for test data (only used if verify is on)
//       RdmaAddr  RDMA buffer address (0 if not using RDMA)
//       UInt32    buffsize
//    Returns:
//       Test data buffer (if not sent using RDMA)
void RcvMsg::handleRead(MsgWorker *mwP)
{
  if (mwP->rtestBuff.getBuffP() == NULL)
    Error("rtestBuff was not allocated");

  // If verifying contents, generate test data according to specified seed.
  // Otherwise, send the same contents every time.
  UInt64 seed = msgBuff.getUInt64();
  if (verify)
    mwP->rtestBuff.fillBuff(seed);

#ifdef RDMA
  if (useRdma != rOff && useRdma != rInline)
  {
    RdmaAddr raddr = msgBuff.getRdmaAddr();
    UInt32 rlen = msgBuff.getUInt32();
    timeLine->rdStartStamp = getStamp();
    connP->rdmaWrite(&mwP->rtestBuff, raddr, rlen, &mwP->pwait);
    timeLine->rdFinStamp = getStamp();
    sendReply(NULL, errText, &mwP->pwait);
  }
  else
#endif
  {
    sendReply(&mwP->rtestBuff, errText, &mwP->pwait);
  }
}


// Message handler for mtConnect.  This is sent from the admin node to all
// clients, and tells them to make connections to all servers.
//    Input:
//       UInt32 nServers
//       Array[nServers]
//         String hostname
//         IpAddr IP address (native host format)
//         Int32 nPorts
//         Array[nPorts]
//           RdmaPortInfo pinfo
//    Returns:
//       Nothing
void RcvMsg::handleConnect()
{
  int j, k, nRdmaPorts, nServers = 0;
  IpAddr iaddr;
  string hname, errmsg;
  multimap<IpAddr, Target *>::iterator node;
  Target *targP;
  ostringstream os;

  if (startAdminReq())
    return;

  // Target nodes shouldn't have a client table; that's only for admin
  // nodes.
  if (!clientNodes.empty() || !allNodes.empty())
    Error("nodes table not empty");

  // Remove any broken connections from server table.  Mark the other nodes
  // inactive initially.
  for (node = serverNodes.begin(); node != serverNodes.end(); )
  {
    targP = node->second;
    if (targP->connP == NULL || targP->connP->isBroken())
    {
      delete targP;
      serverNodes.erase(node++);
    }
    else
    {
      targP->active = false;
      ++node;
    }
  }

  nServers = msgBuff.getUInt32();
  for (j = 0; j < nServers; j++)
  {
    hname = msgBuff.getString();
    iaddr = msgBuff.getIpAddr();
    nRdmaPorts = msgBuff.getInt32();
    set<RdmaPortInfo> remoteRdmaPinfo;
    for (k = 0; k < nRdmaPorts; k++)
    {
      RdmaPortInfo pinfo;
      pinfo.getBuff(&msgBuff);
      remoteRdmaPinfo.insert(pinfo);
    }

    // If this node is already in the server table, then we don't need to
    // connect to it here.  Mark it active so that it won't be deleted.
    // If we have multiple connections to the same IP address, only mark
    // the first "nParallel" connections active.
    pair<multimap<IpAddr, Target *>::iterator,
         multimap<IpAddr, Target *>::iterator> nodes;
    int nConnections = 0;
    nodes = serverNodes.equal_range(iaddr);
    for (node = nodes.first; node != nodes.second; ++node)
    {
      if (nConnections < nParallel)
      {
        node->second->active = true;
        node->second->remPinfo = remoteRdmaPinfo;
      }
      nConnections++;
    }
    if (nConnections > 0)
      continue;

    // This node isn't in table, so connect to it and add to table
    targP = new Target(hname, iaddr);
    targP->remPinfo = remoteRdmaPinfo;
    errmsg = targP->makeConnection();
    if (!errmsg.empty())
    {
      os << "Cannot connect to " << hname << ": " << errmsg << endl;
      delete targP;
    }
    else
      serverNodes.insert(pair<IpAddr, Target *>(iaddr, targP));
  }

  // Shut down any connections to servers that were not mentioned in the
  // message argument or exceeded the parallel count.
  for (node = serverNodes.begin(); node != serverNodes.end(); )
  {
    targP = node->second;
    if (targP->active)
      ++node;
    else
    {
      delete targP;
      serverNodes.erase(node++);
    }
  }

  // If more than one parallel connection was requested, make additional
  // connections if necessary.  They will look like extra serverNodes.
  if (nParallel > 1)
  {
    multimap<IpAddr, Target *>::const_iterator node;
    map<IpAddr, Target *> servers;
    map<IpAddr, Target *>::const_iterator srv;

    // Make a table of unique server IP addresses
    for (node = serverNodes.begin(); node != serverNodes.end(); ++node)
      servers[node->second->iaddr] = node->second;

    // For each unique address, count the number of existing connections
    // and add more if necessary.
    for (srv = servers.begin(); srv != servers.end(); ++srv)
      for (j = serverNodes.count(srv->first); j < nParallel; j++)
      {
        targP = new Target(srv->second->hostname, srv->first);
        targP->remPinfo = srv->second->remPinfo;
        errmsg = targP->makeConnection();
        if (!errmsg.empty())
        {
          os << "Cannot make parallel connection to " << srv->second->hostname
             << ": " << errmsg << endl;
          delete targP;
        }
        else
          serverNodes.insert(pair<IpAddr, Target *>(srv->first, targP));
      }
  }

#ifdef RDMA
  // Make RDMA connections if necessary
  if (useRdma != rOff)
  {
    if (!rdmaInitialized)
      os << "RDMA is not initialized" << endl;
    else
      for (node = serverNodes.begin(); node != serverNodes.end(); ++node)
      {
        targP = node->second;
        errmsg = targP->connP->rdmaClientConnect(&targP->remPinfo);
        if (!errmsg.empty())
          os << "Cannot make RDMA connection to " << targP->hostname
             << ": " << errmsg << endl;
      }
  }
#endif

  endAdminReq();
  sendReply(NULL, os.str());
}


// Message handler for mtReset
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleReset()
{
  multimap<IpAddr, Target *>::iterator node;

  if (startAdminReq())
    return;
  if (!clientNodes.empty() || !allNodes.empty())
    Error("nodes table not empty");
  for (node = serverNodes.begin(); node != serverNodes.end(); )
  {
    delete node->second;
    serverNodes.erase(node++);
  }
  endAdminReq();
  sendReply(NULL);
}


// Message handler for mtRdmaDone - Close RDMA connections to servers
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleRdmaDone()
{
#ifdef RDMA
  RcvMsg *rmsgP;
  Target *targP;
  multimap<IpAddr, Target *>::iterator node;
  if (startAdminReq())
    return;
  for (node = serverNodes.begin(); node != serverNodes.end(); ++node)
  {
    targP = node->second;
    targP->connP->rdmaSendCMDiscReq();

    // Shut down RDMA connections in two phases.  In the first phase,
    // connections are broken.  This will ensure that no receives occur
    // while the buffers are being deleted in the second phase.
    targP->connP->rdmaDisconnect();
    rmsgP = targP->sendm(mtRdmaDisconn, NULL, 0);
    rmsgP->showError();
    delete rmsgP;

    targP->connP->rdmaCleanup();
    rmsgP = targP->sendm(mtRdmaCleanup, NULL, 0);
    rmsgP->showError();
    delete rmsgP;
  }
  endAdminReq();
  sendReply(NULL);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtRdmaConn - set up server-side RDMA connection
//    Input:
//       UInt32 client's queue pair number
//       UInt32 client's location identifier
//       UInt32 client's receive buffer key
//       UInt32 client's max_qp_rd_atom
//       UInt32 client's TCP connection number (for ConnKey)
//       IpAddr client's value for my IP address (for ConnKey)
//       Int32  client's rconnTab index for this connection
//       RdmaPortInfo client's port info
//       RdmaPortInfo desired port on server
//    Returns:
//       UInt32 server's queue pair number
//       UInt32 server's location identifier
//       UInt32 server's receive buffer key
//       UInt32 server's max_qp_rd_atom
//       Int32  server's rconnTab index for this connection
//       RdmaPortInfo port chosen on server
void RcvMsg::handleRdmaConn()
{
#ifdef RDMA
  if (!rdmaInitialized)
    Error("RDMA connect request received, but RDMA is not initialized");
  connP->rdmaServerConnect(this);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtRdmaGetBuffs
//    Input:
//       None
//    Returns:
//       UInt32 nEntries
//       nEntries * RdmaAddr - RDMA memory buffers to use in write tests
void RcvMsg::handleRdmaGetBuffs()
{
#ifdef RDMA
  unsigned int n;
  DataBuff db(sizeof(UInt32) + nTesterThreads * sizeof(RdmaAddr));
  char *buffP;

  if (!rdmaInitialized)
    Error("RDMA connect request received, but RDMA is not initialized");

  // Give the client node some RDMA memory buffers to use in write tests.
  // Keep track of what we have given out so that we can return the
  // memory if the connection breaks.
  db.putUInt32(nTesterThreads);
  for (n = 0; n < nTesterThreads; n++)
  {
    buffP = poolGet(buffsize);
    db.putRdmaAddr(buffP);
    connP->rdmaGiven(buffP);
  }
  sendReply(&db);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtRdmaDisconnCM
//    Input:
//       Int32 connNdx
//    Returns:
//       Nothing
void RcvMsg::handleRdmaDisconnCM()
{
#ifdef RDMA
  connP->rdmaRecvCMDiscReq(this);
  sendReply(NULL);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtRdmaDisconn - tear down RDMA connection
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleRdmaDisconn()
{
#ifdef RDMA
  connP->rdmaDisconnect();
  sendReply(NULL);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Message handler for mtRdmaCleanup
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleRdmaCleanup()
{
#ifdef RDMA
  connP->rdmaCleanup();
  sendReply(NULL);
#else
  sendReply(NULL, "RDMA not supported");
#endif
}


// Break any existing TCP connection for this target
static void disconnect(pair<IpAddr, Target *> p)
{
  Target *targP = p.second;
  if (targP->connP == NULL || targP->connP->isBroken())
    return;
  targP->connP->connShutdown();
  targP->connP->releaseConn();
  targP->connP = NULL;
}


// Message handler for mtParms
//    Input:
//       UInt32 testTime
//       UInt32 buffsize
//       UInt32 socksize
//       UInt32 nTesterThreads
//       UInt32 nParallel
//       UInt32 useRdma
//       UInt32 useCM
//       Int32  sinline
//       UInt32 verify
//       UInt32 nClients
//       Int32  remoteDebugLevel
//       Int32  maxRdma
//       Int32  isServer
//    Returns:
//       Int32 nPorts
//       Array[nPorts]
//         RdmaPortInfo pinfo
void RcvMsg::handleParms()
{
  int newSocksize, newNParallel, newMaxRdma, lev;
  unsigned int newNTesterThreads, newNClients;
  RdmaMode newUseRdma;
  bool newCM, newSinline;
  string errText;

  if (startAdminReq())
    return;

  testTime = msgBuff.getUInt32();
  buffsize = msgBuff.getUInt32();
  newSocksize = msgBuff.getUInt32();
  newNTesterThreads = msgBuff.getUInt32();
  newNParallel = msgBuff.getUInt32();
  newUseRdma = static_cast<RdmaMode>(msgBuff.getUInt32());
  newCM = msgBuff.getUInt32() != 0;
  newSinline = msgBuff.getUInt32() != 0;
  verify = msgBuff.getUInt32() != 0;
  newNClients = msgBuff.getUInt32();
  lev = msgBuff.getInt32();
  newMaxRdma = msgBuff.getInt32();
  IAmServer = msgBuff.getInt32() != 0;

  if (testTime < 1) testTime = 1;
  if (buffsize < 1) buffsize = 1;
  if (buffsize > MAX_BUFFSIZE) buffsize = MAX_BUFFSIZE;
  if (newSocksize > MAX_SOCKSIZE) newSocksize = MAX_SOCKSIZE;
  if (newNTesterThreads < 1) newNTesterThreads = 1;
  if (newNTesterThreads > MAX_TESTERS) newNTesterThreads = MAX_TESTERS;
  if (newNParallel < 1) newNParallel = 1;
  if (newNParallel > MAX_PARALLEL) newNParallel = MAX_PARALLEL;
  if (lev >= 0) debugLevel = lev;
  if (newMaxRdma <= 0) newMaxRdma = MAXRDMA_UNLIMITED;

  // If socket buffer size changes, close any existing server connections
  // so that they will be re-opened with the proper settings.  This will
  // also ensure that the server has found out the new socksize value and
  // used that setting on his end.  Also, tell the listen/accept thread to
  // switch to the new size.
  if (newSocksize != socksize)
  {
    socksize = newSocksize;
    for_each(serverNodes.begin(), serverNodes.end(), disconnect);
    if (laThreadP != NULL)
      laThreadP->updateSocksize();
  }

#ifdef RDMA
  // If any settings change which will affect RDMA connections (queue
  // sizes, memory allocation, etc.), shut down RDMA so that the
  // connections will be re-established with the proper values.
  if (nTesterThreads != newNTesterThreads || nParallel != newNParallel ||
      nClients != newNClients || newUseRdma != useRdma ||
      newMaxRdma != maxRdma || useCM != newCM || newSinline != sinline)
    rdmaShutdown();
#endif
  nTesterThreads = newNTesterThreads;
  nParallel = newNParallel;
  nClients = newNClients;
  useRdma = newUseRdma;
  maxRdma = newMaxRdma;
  useCM = newCM;
  sinline = newSinline;

#ifdef RDMA
  // Start up or shut down RDMA devices
  if (useRdma != rOff)
    errText = rdmaStart();
  else
    rdmaShutdown();
#else
  if (useRdma != rOff)
    errText = "RDMA is not supported";
#endif

  // If we don't have enough tester threads, start up some new ones.
  // If we have too many, wake them up so that some of them will exit.
  thLock(&testerMutex);
  while (testerTab.size() < nTesterThreads)
  {
    thUnlock(&testerMutex);
    Tester *tP = new Tester();
    tP->init();
    thLock(&testerMutex);
    if (!testerTab.insert(tP).second)
      Error("duplicate testerTab entry");
  }
  if (testerTab.size() > nTesterThreads)
  {
    thBcast(&testerCond);
    while (testerTab.size() > nTesterThreads)
      thWait(&testerCond, &testerMutex);
  }
  thUnlock(&testerMutex);
  endAdminReq();

#ifdef RDMA
  // Return list of RDMA ports
  unsigned int len;
  RdmaPortInfo pinfo;
  vector<RdmaPort *>::const_iterator rpi;

  len = 0;
  for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
  {
    pinfo = RdmaPortInfo(*rpi);
    len += pinfo.calcPortInfoLen();
  }
  msgBuff.newBuff(sizeof(Int32) + len);
  msgBuff.putInt32(rdmaPortTab.size());
  for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
  {
    pinfo = RdmaPortInfo(*rpi);
    pinfo.putBuff(&msgBuff);
  }
#else
  msgBuff.newBuff(sizeof(Int32));
  msgBuff.putInt32(0);
#endif
  sendReply(&msgBuff, errText);
}


// Message handler for mtAlloc - Allocate buffers needed for test
//    Input:
//       Int32 nConnections
//    Returns:
//       Nothing
void RcvMsg::handleAlloc()
{
  if (startAdminReq())
    return;

#ifdef RDMA
  int nConnections = msgBuff.getInt32();
  if (nConnections < 0)
    Error("Invalid nConnections value in mtAlloc");

  // Allocate RDMA memory pool
  rdmaMemoryAlloc(nConnections);
#endif

  // On server nodes, allocate a test data buffer for each worker to use
  // for replying to read requests.  If RDMA is enabled, this will be
  // allocated from the RDMA memory pool.  Also, for RDMA, allocate another
  // buffer to use for fetching data in nwrite requests.  If inline RDMA
  // messages are enabled, allocate a message buffer for inline data.
  if (IAmServer)
  {
    vector<MsgWorker *>::iterator worker;
    for (worker = workerTab.begin(); worker != workerTab.end(); ++worker)
    {
      MsgWorker *w = *worker;
      w->rtestBuff.initBuff(poolGet(buffsize), buffsize);
      w->rtestBuff.fillBuff(randSeed());
      w->getRdmaBuff();
    }
  }
  endAdminReq();
  sendReply(NULL);
}


// Message handler for mtFree - Free buffers allocated by mtAlloc
//    Input:
//       None
//    Returns:
//       Nothing
void RcvMsg::handleFree()
{
  if (startAdminReq())
    return;

  vector<MsgWorker *>::iterator worker;
  for (worker = workerTab.begin(); worker != workerTab.end(); ++worker)
  {
    MsgWorker *w = *worker;
    poolFree(w->rtestBuff.getBuffP());
    w->rtestBuff.initBuff(NULL, 0);
    w->freeRdmaBuff();
  }

#ifdef RDMA
  rdmaMemoryFree();
#endif

  endAdminReq();
  sendReply(NULL);
}


// Message handler for mtTest
//    Input:
//       UInt32 testType
//    Returns:
//       UInt64 totBytes
//       UInt32 CPU idle percentage
//       Histogram response times
//       Histogram latency times
void RcvMsg::handleTest()
{
  TType ttin, tt;
  multimap<IpAddr, Target *>::const_iterator node;
  string errText;
  Histogram hist;
  Histogram lat;

  if (startAdminReq())
    return;
  if (serverNodes.empty())
    errText = "no server nodes for mtTest";

  // Pick up test type from incoming message
  ttin = static_cast<TType>(msgBuff.getUInt32());
  if (ttin >= ttLast && errText.empty())
    errText = "invalid test type";

  if (errText.empty())
  {
    // Run the test.  Pass a TestReq to each tester thread, and wait for
    // them all to complete it.
    HTime endTime;
    UInt64 totBytes;
    TestReq *trP;
    set<Tester *>::iterator tst;

    thLock(&testerMutex);
    if (testerTab.empty())
      Error("no tester threads");
    endTime = getTime() + sectoht(testTime);
    testActive = true;

    // The serverNodes table is ordered by IP address, and might contain
    // more than one connection per address.  We want round-robin sends to
    // go to each server before repeating on parallel connections, so make
    // a new table of addresses with proper sort order.  Note that the
    // serverNodes table will not change in the middle of a test, so we
    // don't need a mutex to access it here.
    vector<SortedTarget> rrNodes;
    IpAddr lastAddr;
    int ndx = 0;

    rrNodes.reserve(serverNodes.size());
    for (node = serverNodes.begin(); node != serverNodes.end(); ++node)
    {
      Target *targP = node->second;
      if (targP->iaddr != lastAddr)
      {
        lastAddr = targP->iaddr;
        ndx = 0;
      }
      rrNodes.push_back(SortedTarget(ndx, targP));
      ndx++;
    }
    sort(rrNodes.begin(), rrNodes.end(), SortedTarget::comp);
    vector<SortedTarget>::const_iterator rnode = rrNodes.begin();
    int nServers = rrNodes.size() / nParallel;

    for (tst = testerTab.begin(); tst != testerTab.end(); ++tst)
    {
      nTestersWorking++;

      // For the read/write test, half the workers are readers and half are
      // writers.
      if (ttin == ttRW)
        tt = nTestersWorking > testerTab.size() / 2 ? ttWrite : ttRead;
      else
        tt = ttin;
      trP = new TestReq(tt);

      // If test isn't round-robin, assign one server target.
      // Otherwise assign all of them.  With parallel sockets, give
      // separate sets of connections to each thread if possible.
      int ns = (tt == ttSwrite || tt == ttSread) ? 1 : nServers;
      for (ndx = 0; ndx < ns; ndx++)
      {
        // For RDMA write tests, reserve memory on other nodes to write
        // into.  We avoid the extra round trip required by NSD-style
        // writes by choosing the remote memory location on the sending
        // side, and then telling the target where to find the data.
        RdmaAddr tBuff;
#ifdef RDMA
        if (useRdma != rOff && (tt == ttWrite || tt == ttSwrite))
          tBuff = rnode->targP->connP->getRemoteBuff();
#endif

        trP->testNodes.push_back(TNodeInfo(rnode->targP, tBuff));
        rnode++;
        if (rnode == rrNodes.end())
          rnode = rrNodes.begin();
      }

      // Hand off the test request to a tester thread
      (*tst)->doTest(trP);

#ifdef RDMA
      // Return RDMA memory buffers if we acquired them
      if (useRdma != rOff && (tt == ttWrite || tt == ttSwrite))
      {
        list<TNodeInfo>::iterator tnode;
        for (tnode = trP->testNodes.begin();
             tnode != trP->testNodes.end();
             ++tnode)
          tnode->targP->connP->freeRemoteBuff(tnode->tBuff);
      }
#endif
    }
    thBcast(&testerCond);

    // Sleep until end of test, and then tell the testers to stop
    thUnlock(&testerMutex);
    sleepUntil(endTime);
    thLock(&testerMutex);
    testActive = false;
    while (nTestersWorking > 0)
      thWait(&testerCond, &testerMutex);

    // Tally the results from the tester threads
    totBytes = 0;
    while (!doneList.empty())
    {
      trP = doneList.front();
      doneList.pop_front();
      totBytes += trP->totBytes;
      hist.addHist(&trP->hist);
      lat.addHist(&trP->lat);
      if (errText.empty())
        errText = trP->errText;
      delete trP;
    }
    thUnlock(&testerMutex);

    msgBuff.newBuff(sizeof(UInt64) + sizeof(UInt32) + hist.calcLen() + lat.calcLen());
    msgBuff.putUInt64(totBytes);
    msgBuff.putUInt32(idleTime);
    hist.putBuff(&msgBuff);
    lat.putBuff(&msgBuff);
  }

  endAdminReq();
  sendReply(&msgBuff, errText);
}


// Message handler for mtStatus
//    Input:
//       None
//    Returns:
//       String ServerStatus
void RcvMsg::handleStatus()
{
  ostringstream os;
  multimap<IpAddr, Target *>::iterator node;

  if (startAdminReq())
    return;
  if (!serverNodes.empty())
  {
    os << " -> ";
    for (node = serverNodes.begin(); node != serverNodes.end(); ++node)
      os << node->second->hostname << " ";
  }
  os << endl;

#ifdef RDMA
  if (useRdma != rOff && !rdmaPortTab.empty())
  {
    vector<RdmaPort *>::const_iterator rpi;
    for (rpi = rdmaPortTab.begin(); rpi != rdmaPortTab.end(); ++rpi)
      os << "    " << (*rpi)->devString() << endl;
  }
#endif

  string s = os.str();
  msgBuff.newBuff(calcLen(s));
  msgBuff.putString(s);
  endAdminReq();
  sendReply(&msgBuff);
}


// Message handler for mtIdlePct
//    Input:
//       None
//    Returns:
//       UInt32 CPU idle percentage
void RcvMsg::handleIdlePct()
{
  msgBuff.newBuff(sizeof(UInt32));
  msgBuff.putUInt32(idleTime);
  sendReply(&msgBuff);
}


// Dispatch a received message to the appropriate handler.  Simple messages
// are handled here.
void RcvMsg::dispatch(MsgWorker *mwP)
{
  switch (msgType)
  {
    case mtVersion:
      handleVersion();
      break;

    case mtKill:
      handleKill();
      break;

    case mtWrite:
      handleWrite(mwP);
      break;

    case mtRdmaWrite:
      handleRdmaWrite(mwP);
      break;

    case mtNwrite:
      handleNwrite(mwP);
      break;

    case mtGetdata:
      handleGetdata(mwP);
      break;

    case mtRead:
      handleRead(mwP);
      break;

    case mtConnect:
      handleConnect();
      break;

    case mtReset:
      handleReset();
      break;

    case mtRdmaDone:
      handleRdmaDone();
      break;

    case mtRdmaConn:
      handleRdmaConn();
      break;

    case mtRdmaGetBuffs:
      handleRdmaGetBuffs();
      break;

    case mtRdmaDisconnCM:
      handleRdmaDisconnCM();
      break;

    case mtRdmaDisconn:
      handleRdmaDisconn();
      break;

    case mtRdmaCleanup:
      handleRdmaCleanup();
      break;

    case mtParms:
      handleParms();
      break;

    case mtAlloc:
      handleAlloc();
      break;

    case mtFree:
      handleFree();
      break;

    case mtTest:
      handleTest();
      break;

    case mtStatus:
      handleStatus();
      break;

    case mtStatOn:
      collectStats = true;
      (void) cpuIdle();
      sendReply(NULL);
      break;

    case mtStatOff:
      collectStats = false;
      idleTime = cpuIdle();
      sendReply(NULL);
      break;

    case mtIdlePct:
      handleIdlePct();
      break;

    default:
      Error("Invalid message type " << msgType << " from " << connP->destName());
  }
}


// Destructor for message worker object.  Free any memory pool buffers.
MsgWorker::~MsgWorker()
{
  freeRdmaBuff();
  poolFree(rtestBuff.getBuffP());
}


// Message worker thread body
int MsgWorker::threadBody()
{
  RcvMsg *rmsgP;
#ifdef RDMA
  this->pwait.tid = (int)syscall(SYS_gettid);
#endif
  thLock(&workerMutex);
  while (true)
  {
    // Wait for a receiver thread to pass us a message.  Don't process bulk
    // messages if almost all of the workers are busy.
    while (msgQueue.empty() &&
           (bulkQueue.empty() || workersActive >= nWorkers - 2) &&
           !quitflag)
      thWait(&workerCond, &workerMutex);
    if (quitflag)
      break;
    workersActive++;
    if (msgQueue.empty())
    {
      rmsgP = bulkQueue.front();
      bulkQueue.pop_front();
    }
    else
    {
      rmsgP = msgQueue.front();
      msgQueue.pop_front();
    }

    // Call the message handler
    thUnlock(&workerMutex);
    rmsgP->dispatch(this);
    delete rmsgP;
    thLock(&workerMutex);
    workersActive--;
  }
  thUnlock(&workerMutex);
  return 0;
}


#ifdef RDMA
// On server nodes, reserve an RDMA memory buffer and message buffer for
// this worker thread.  The RDMA buffer is used as the destination for an
// RDMA read when the thread receives an nwrite RPC.  The message buffer is
// only allocated when RDMA is set to "all" or "inline", and is used to
// send reply messages.
void MsgWorker::getRdmaBuff()
{
  if (!rdmaInitialized)
    return;
  if (!IAmServer)
    Error("getRdmaBuff called on non-server");
  if (rdBuffP != NULL)
    Error("invalid call to getRdmaBuff");

  rdLen = buffsize;
  rdBuffP = poolGet(rdLen);

  pwait.mbufP = (useRdma == rAll || useRdma == rInline) ?
    mbufGet(mbufSize) : NULL;
}


// If an RDMA memory buffer was allocated, free it
void MsgWorker::freeRdmaBuff()
{
  poolFree(rdBuffP);
  rdLen = 0;
  rdBuffP = NULL;
  mbufFree(pwait.mbufP);
  pwait.mbufP = NULL;
}
#else
void MsgWorker::getRdmaBuff() {}
void MsgWorker::freeRdmaBuff() {}
#endif // RDMA


// Tester thread body
int Tester::threadBody()
{
  HTime startStamp, endStamp;
  TimeLine *timeLine = new TimeLine();
  list<TNodeInfo>::iterator tnode;
  Target *targP;
  RdmaAddr tBuff;
  RcvMsg *replyP = NULL;
  unsigned int datalen = 0;
  char *dataP = NULL;
  DataBuff db, testBuff;
  PollWait pwait;
  UInt64 seed = randSeed();
  bool isRead;

  thLock(&testerMutex);

  while (true)
  {
    // Wait for a work request or a notification that too many threads
    // are running.
    while (reqP == NULL && testerTab.size() <= nTesterThreads)
      thWait(&testerCond, &testerMutex);
    if (testerTab.size() > nTesterThreads)
      break;
    thUnlock(&testerMutex);

    if (reqP->testNodes.empty())
      Error("No servers for tester thread");

    // Initialize test buffer for sends.  If RDMA is enabled, this buffer
    // will be allocated in registered memory so that RDMA can be done
    // directly from it.
    testBuff.initBuff(poolGet(buffsize), buffsize);
    testBuff.fillBuff(seed);

    // If using RDMA, get a registered memory buffer to use for reads
    isRead = (reqP->tt == ttRead || reqP->tt == ttSread);
    if (isRead)
    {
      if (useRdma != rOff)
      {
        datalen = buffsize;
        dataP = poolGet(datalen);
      }
      else
      {
        datalen = 0;
        dataP = NULL;
      }
    }

#ifdef RDMA
    // Get a registered message buffer for sends, if necessary
    if (useRdma == rAll || useRdma == rInline)
      pwait.mbufP = mbufGet(mbufSize);
#endif

    // Move to a random starting position in the test nodes list
    thLock(&globalMutex);
    int spos = random();
    thUnlock(&globalMutex);
    tnode = reqP->testNodes.begin();
    for (spos = spos % reqP->testNodes.size(); spos > 0; spos--)
      if (++tnode == reqP->testNodes.end())
        tnode = reqP->testNodes.begin();

    // Run the test
    while (testActive)
    {
      timeLine = new TimeLine();
      targP = tnode->targP;
      tBuff = tnode->tBuff;
      tnode++;
      if (tnode == reqP->testNodes.end())
        tnode = reqP->testNodes.begin();

      startStamp = collectStats ? getStamp() : 0;
      switch (reqP->tt)
      {
        case ttWrite:
        case ttSwrite:
          if (useRdma == rOff)
          {
            replyP = targP->sendm(mtWrite, &testBuff, NULL, NULL, 0, timeLine);
          }
#ifdef RDMA
          else if (useRdma == rInline)
          {
            // Send the data inline with the Write message.  Since the data
            // is already in a registered memory buffer, pass it using
            // auxBuff so that it won't be copied in sendit().
            db.initBuff(NULL, 0);
            db.setAux(testBuff.getBuffP(), testBuff.getBufflen());
            replyP = targP->sendm(mtWrite, &db, &pwait, NULL, 0, timeLine);
            db.setAux(NULL, 0);
          }
          else
          {
            // Write directly to remote buffer
            if (tBuff == 0)
              Error("remote RDMA buffer missing");
            timeLine->rdStartStamp = getStamp();
            targP->connP->rdmaWrite(&testBuff, tBuff, buffsize, &pwait);
            timeLine->rdFinStamp = getStamp();

            // Tell the other side where we wrote the data
            db.newBuff(sizeof(RdmaAddr) + sizeof(UInt32));
            db.putRdmaAddr(tBuff);
            db.putUInt32(buffsize);
            replyP = targP->sendm(mtRdmaWrite, &db, &pwait, NULL, 0, timeLine);
          }
#endif
          break;

        case ttNwrite:
          // Pass test buffer address into MsgRecord so that Getdata can
          // retrieve it.
          db.newBuff(sizeof(RdmaAddr) + 2 * sizeof(UInt32));
          db.putRdmaAddr(testBuff.getBuffP());
          db.putUInt32(testBuff.getBufflen());
          replyP = targP->sendm(mtNwrite, &db, &pwait, testBuff.getBuffP(),
                                testBuff.getBufflen(), timeLine);
          break;

        case ttRead:
        case ttSread:
          db.newBuff(sizeof(UInt64) + sizeof(RdmaAddr) + sizeof(UInt32));
          db.putUInt64(seed);
          db.putRdmaAddr(dataP);
          db.putUInt32(datalen);
          replyP = targP->sendm(mtRead, &db, &pwait, NULL, 0, timeLine);
          break;

        default:
          Error("invalid test type: " << reqP->tt);
          break;
      }

      if (!replyP->errText.empty())
      {
        reqP->errText = replyP->errText;
        delete replyP;
        if (dataP != NULL)
          poolFree(dataP);
#ifdef RDMA
        if (pwait.mbufP != NULL)
        {
          mbufFree(pwait.mbufP);
          pwait.mbufP = NULL;
        }
#endif
        break;
      }

      if (collectStats && startStamp != 0)
      {
        endStamp = getStamp();
        reqP->hist.addEntry(endStamp - startStamp);
        reqP->totBytes += buffsize + MSG_HDRSIZE;
        // Handle timeLine
        timeLine = replyP->timeLine;
        // Only take into account if the timestamps are reasonable. Timestamps could overflow and lead to wrong number.
        // if (timeLine->msgSendStamp <= timeLine->replyRecvStamp && timeLine->msgRecvStamp <= timeLine->replySendStamp \
        //     && timeLine->rdStartStamp <= timeLine->rdFinStam)
        // {
        HTime networkDelay = timeLine->getNetworkDelay();
        Logt(3, "NetworkDelay: " << networkDelay << ", msgId: " << replyP->msgId << \
                ", rdStart: " << timeLine->rdStartStamp << ", rdFin: " << timeLine->rdFinStamp << \
                ", msgSend: " << timeLine->msgSendStamp << ", msgRecv: " << timeLine->msgRecvStamp << \
                ", replySend: " << timeLine->replySendStamp << ", replyRecv: " << timeLine->replyRecvStamp);
        reqP->lat.addEntry(networkDelay);
        // }
      }

      if (verify)
      {
        // For a reads, we tell the other node what seed to use to generate
        // the test data, and verify that is what we got.  For writes, the
        // other node picks up the seed from the first double-word of the
        // test buffer that we send, verifies the contents, and tells us
        // the seed.  It must much the seed that we used to generate the
        // buffer.
        if (isRead)
        {
          if (!replyP->msgBuff.verifyBuff(seed))
            Error("Data verification failed");
          seed += SCRAMBLE;
        }
        else
        {
          if (replyP->msgBuff.getUInt64() != seed)
            Error("Data verification error");

          // When verifying contents, generate new test data for each
          // message.  Don't use randSeed() here because we don't want to
          // contend for the global mutex.
          seed += SCRAMBLE;
          testBuff.fillBuff(seed);
        }
      }
      delete replyP;
    }

    // Report results to main thread
    thLock(&testerMutex);
    doneList.push_back(reqP);
    reqP = NULL;
    if (nTestersWorking == 0)
      Error("doneList overflow");
    nTestersWorking--;
    if (nTestersWorking == 0)
      thBcast(&testerCond);

    if (dataP != NULL)
    {
      poolFree(dataP);
      dataP = NULL;
    }
#ifdef RDMA
    if (pwait.mbufP != NULL)
    {
      mbufFree(pwait.mbufP);
      pwait.mbufP = NULL;
    }
#endif
    poolFree(testBuff.getBuffP());
  }

  if (testerTab.erase(this) != 1)
    Error("thread pointer not found in testerTab");
  thBcast(&testerCond);
  thUnlock(&testerMutex);
  return 0;
}


// Tell tester thread to do some work.  This doesn't wake up the thread.
// Caller must broadcast testerCond to do that.  Tester will put updated
// TestReq on doneList when finished.  Caller must hold testerMutex.
void Tester::doTest(TestReq *trP)
{
  if (reqP != NULL)
    Error("tester thread busy");
  reqP = trP;
}


// Listen/accept thread body
int ListenAccept::threadBody()
{
  int rc;
  Sock lsock, sock;
  linger ling;
  sockaddr_storage saddr;
  sockaddr *saddrP = reinterpret_cast<sockaddr *>(&saddr);
  socklen_t alen;
  PollSock ps;
  IpAddr iaddr;

  // Loop, opening a listen socket
  while (!quitflag)
  {
    if ((lsock = socket(addrFamily, SOCK_STREAM, 0)) == INVALID_SOCK)
      Errorm("socket open");

    // Set to recycle addresses
    if ((setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)
      Errorm("setsockopt SO_REUSEADDR");

    // Set the socket to not linger after the program exits
    ling.l_onoff = 1;
    ling.l_linger = 0;
    if (setsockopt(lsock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) < 0)
      Errorm("setsockopt SO_LINGER");

    // Set send/receive buffer sizes
    setSockSizes(lsock);

    // Bind the socket
    iaddr.setAny();
    if (bind(lsock, iaddr.toSockaddr(port, &saddr), iaddr.getSocklen()) < 0)
      Errorm("bind");
    if (listen(lsock, 128) < 0) Errorm("listen");

    // Set for non-blocking IO
    setSockNonblocking(lsock);

    // Tell updateSocksize that we have adjusted the size
    thLock(&globalMutex);
    currsize = socksize;
    thBcast(&globalCond);
    thUnlock(&globalMutex);

    // Loop, accepting connections
    while (!quitflag)
    {
      // If socket buffer size changes, close the listen socket and break
      // out of accept loop to go back and re-open socket with correct size
      // (since size must be set before listen call).
      if (socksize != currsize)
      {
        if (close(lsock) < 0) Errorm("close lsock");
        break;
      }

      // Wait for a connection.  Use a timeout on poll, so that if we miss
      // the signal for a socksize change, we'll wake up soon and notice
      // it.  Using ppoll would be better, but not all systems support that.
      ps.fd = lsock;
      ps.events = POLLIN;
      ps.revents = 0;
      rc = poll(&ps, 1, 1000);
      if (rc < 0)
      {
        if (errno == EINTR)
          continue;
        Errorm("poll for incoming connection");
      }
      if (rc == 0)
        continue;

      // Accept anybody who connects
      alen = sizeof(saddr);
      sock = accept(lsock, saddrP, &alen);
      if (sock == INVALID_SOCK)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ECONNABORTED || errno == EINTR)
          continue;
        Errorm("accept");
      }
      iaddr.loadSockaddr(saddrP);
      Log("Connection from " << iaddr.toString());

      // Don't delay sending messages
      if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
        Errorm("setsockopt TCP_NODELAY");

      // Set for non-blocking IO
      setSockNonblocking(sock);

      // Hand off the socket to a receiver thread
      pickReceiver()->addConn(sock, new TcpConn(sock, iaddr));
    }
  }
  return 0;
}


// Tell the listen/accept thread that the socket send/receive buffer size
// has changed, so the listen socket must be closed and re-opened to set
// the new size.
void ListenAccept::updateSocksize()
{
  if (socksize == currsize)
    return;

  // Wake up the thread, if it is in poll.  If it is just about to start
  // the poll, it could miss this signal, but it will time out soon after
  // that and notice the change.
  thKill(getThread(), SIGUSR1);

  // Wait until the thread has picked up the new size.
  thLock(&globalMutex);
  while (socksize != currsize)
    thWait(&globalCond, &globalMutex);
  thUnlock(&globalMutex);
}

#ifdef RDMA
const char *ibv_wr_opcode_str(enum ibv_wr_opcode opcode)
{
  const char *strP;
  switch (opcode)
  {
    case IBV_WR_RDMA_WRITE: strP = "IBV_WR_RDMA_WRITE";     break;
    case IBV_WR_RDMA_READ:  strP = "IBV_WR_RDMA_READ";      break;
    case IBV_WR_SEND:       strP = "IBV_WR_SEND";           break;
    default:                strP = "unknown ibv_wr_opcode"; break;
  }
  return strP;
}

#ifndef IBV_WC_LOCAL_INV
#define IBV_WC_LOCAL_INV 6
#endif

const char *ibv_wc_opcode_str(enum ibv_wc_opcode opcode)
{
  const char *strP;
  switch (opcode)
  {
    case IBV_WC_SEND:               strP = "IBV_WC_SEND";               break;
    case IBV_WC_RDMA_WRITE:         strP = "IBV_WC_RDMA_WRITE";         break;
    case IBV_WC_RDMA_READ:          strP = "IBV_WC_RDMA_READ";          break;
    case IBV_WC_COMP_SWAP:          strP = "IBV_WC_COMP_SWAP";          break;
    case IBV_WC_FETCH_ADD:          strP = "IBV_WC_FETCH_ADD";          break;
    case IBV_WC_BIND_MW:            strP = "IBV_WC_BIND_MW";            break;
    case IBV_WC_LOCAL_INV:          strP = "IBV_WC_LOCAL_INV";          break;
    case IBV_WC_RECV:               strP = "IBV_WC_RECV";               break;
    case IBV_WC_RECV_RDMA_WITH_IMM: strP = "IBV_WC_RECV_RDMA_WITH_IMM"; break;
    default:                        strP = "IBV_WC_UNKNOWN";            break;
  }
  return strP;
}

#define WC_MAX_STATUS 23
const char *wcStatusStr[WC_MAX_STATUS] =
{
  "IBV_WC_SUCCESS", // 0
  "IBV_WC_LOC_LEN_ERR",
  "IBV_WC_LOC_QP_OP_ERR",
  "IBV_WC_LOC_EEC_OP_ERR",
  "IBV_WC_LOC_PROT_ERR",
  "IBV_WC_WR_FLUSH_ERR",
  "IBV_WC_MW_BIND_ERR",
  "IBV_WC_BAD_RESP_ERR",
  "IBV_WC_LOC_ACCESS_ERR",
  "IBV_WC_REM_INV_REQ_ERR",
  "IBV_WC_REM_ACCESS_ERR",
  "IBV_WC_REM_OP_ERR",
  "IBV_WC_RETRY_EXC_ERR",
  "IBV_WC_RNR_RETRY_EXC_ERR",
  "IBV_WC_LOC_RDD_VIOL_ERR",
  "IBV_WC_REM_INV_RD_REQ_ERR",
  "IBV_WC_REM_ABORT_ERR",
  "IBV_WC_INV_EECN_ERR",
  "IBV_WC_INV_EEC_STATE_ERR",
  "IBV_WC_FATAL_ERR",
  "IBV_WC_RESP_TIMEOUT_ERR",
  "IBV_WC_GENERAL_ERR", // 21
  "IBV_WC_UNKNOWN"  // 22 overflow
};

const char *ibv_wc_status_str_nsdperf(enum ibv_wc_status status)
{
  if (status < 0 || status >= WC_MAX_STATUS)
  {
    status = (ibv_wc_status)(WC_MAX_STATUS - 1);
  }
  return wcStatusStr[status];
}

// Handle a work completion event
static void handleCQEvent(ibv_wc *wcP)
{
  PollWait *pwaitP = reinterpret_cast<PollWait *>(wcP->wr_id);

  if (wcP->status != IBV_WC_SUCCESS)
  {
    switch(pwaitP->opcode)
    {
      case IBV_WR_RDMA_WRITE:
      case IBV_WR_RDMA_READ:
        printf("handleCQEvent: error: tid %d opId %llu "
               "status %d %s "
               "ibv_wr_opcode %s "
               "srvBuffP start 0x%llX end 0x%llX "
               "cliBuffP start 0x%llX end 0x%llX "
               "len %u\n",
               pwaitP->tid, pwaitP->opId,
               wcP->status, ibv_wc_status_str_nsdperf(wcP->status),
               ibv_wr_opcode_str(pwaitP->opcode),
               pwaitP->srvBuffP, pwaitP->srvBuffP + pwaitP->buffLen,
               pwaitP->cliBuffP, pwaitP->cliBuffP + pwaitP->buffLen,
               pwaitP->buffLen);
    }

    Logt(4, "RDMA event, qp " << wcP->qp_num << " pwait " << pwaitP
         << " status " << wcP->status);
    pwaitP->wakeup(wcP->status);
    return;
  }

  if (rdmaDebugLevel > 1)
  {
    thLock(&logMutex);
    printf("handleCQEvent: tid %d opId %llu\n",
           pwaitP->tid, pwaitP->opId);
    thUnlock(&logMutex);
  }

  Logt(4, "RDMA event, qp " << wcP->qp_num << " pwait " << pwaitP
       << " op " << wcP->opcode);

  switch(wcP->opcode)
  {
    case IBV_WC_RDMA_WRITE:
    case IBV_WC_RDMA_READ:
    case IBV_WC_SEND:
      pwaitP->wakeup(wcP->status);
      break;

    case IBV_WC_RECV:
      if (pwaitP->rconnP == NULL)
        Error("RDMA receive complete with no connection");
      pwaitP->rconnP->rdRecv(pwaitP, wcP->byte_len);
      break;

    default:
      Error("Invalid opcode " << wcP->opcode << " in WC");
  }
}


// RDMA receiver thread body, one per device
int RdmaReceiver::threadBody()
{
  int j, rc, nEntries = rdmaRecDevP->cqSize;
  ibv_wc *wcP;
  ibv_cq *ecq;
  void *ecqContext;

  if (nEntries < 1)
    Error("bad CQ size");
  wcP = new ibv_wc[nEntries];

  // Wait for events on RDMA completion channel and dispatch them.
  // Exit if requested to die through rdmaRcvState.
  while (rdmaRecDevP->rdmaRcvState == tsRun)
  {
    // Wait for an event on completion channel.  If someone wants us to go
    // away, we could be interrupted here by a SIGUSR1, so don't die if
    // that happens.
    rc = ibv_get_cq_event(rdmaRecDevP->ibCC, &ecq, &ecqContext);
    if (rc == 0)
      ibv_ack_cq_events(ecq, 1);
    else if (rdmaRecDevP->rdmaRcvState != tsRun)
      break;
    else
      Error("ibv_get_cq_event failed");

    // Re-activate completion notifications
    if (ibv_req_notify_cq(ecq, 0) != 0)
      Errorm("ibv_req_notify_cq failed");

    // Grab all entries out of the completion queue.  We do this after
    // requesting notifications but before calling ibv_get_cq_event because
    // otherwise we might miss an entry that was added before notifications
    // were enabled.
    while (true)
    {
      rc = ibv_poll_cq(ecq, nEntries, wcP);
      if (rc == 0)
        break;
      if (rc < 0)
        Error("ibv_poll_cq failed");
      if (rc > nEntries)
        Error("ibv_poll_cq returned too many entries");
      for (j = 0; j < rc; j++)
        handleCQEvent(&wcP[j]);
    }
  }

  // Notify killThread that we are done
  thLock(&globalMutex);
  rdmaRecDevP->rdmaRcvState = tsDead;
  thBcast(&globalCond);
  thUnlock(&globalMutex);

  delete [] wcP;
  Logt(1, "RdmaReceiver thread terminated");
  return 0;
}


// Convert RDMA async event type to string
string rdmaEventToStr(enum ibv_event_type ev)
{
  switch (ev)
  {
    case IBV_EVENT_QP_FATAL:            return "QP_FATAL";
    case IBV_EVENT_QP_REQ_ERR:          return "QP_REQ_ERR";
    case IBV_EVENT_QP_ACCESS_ERR:       return "QP_ACCESS_ERR";
    case IBV_EVENT_COMM_EST:            return "COMM_EST";
    case IBV_EVENT_SQ_DRAINED:          return "SQ_DRAINED";
    case IBV_EVENT_PATH_MIG:            return "PATH_MIG";
    case IBV_EVENT_PATH_MIG_ERR:        return "PATH_MIG_ERR";
    case IBV_EVENT_QP_LAST_WQE_REACHED: return "QP_LAST_WQE_REACHED";
    case IBV_EVENT_CQ_ERR:              return "CQ_ERR";
    case IBV_EVENT_SRQ_ERR:             return "SRQ_ERR";
    case IBV_EVENT_SRQ_LIMIT_REACHED:   return "SRQ_LIMIT_REACHED";
    case IBV_EVENT_PORT_ACTIVE:         return "PORT_ACTIVE";
    case IBV_EVENT_PORT_ERR:            return "PORT_ERR";
    case IBV_EVENT_LID_CHANGE:          return "LID_CHANGE";
    case IBV_EVENT_PKEY_CHANGE:         return "PKEY_CHANGE";
    case IBV_EVENT_SM_CHANGE:           return "SM_CHANGE";
    case IBV_EVENT_CLIENT_REREGISTER:   return "CLIENT_REREGISTER";
    case IBV_EVENT_DEVICE_FATAL:        return "DEVICE_FATAL";
    default:                            return "Unknown";
  }
  return "?";
}


// RdmaAsync constructor
RdmaAsync::RdmaAsync()
{
  // Create a socket pair for waking up thread when it is in poll
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, asyncSocks) < 0)
    Errorm("socketpair");
  setSockNonblocking(asyncSocks[0]);
  setSockNonblocking(asyncSocks[1]);
}


// RdmaAsync destructor
RdmaAsync::~RdmaAsync()
{
  int j;
  for (j = 0; j < 2; j++)
    if (close(asyncSocks[j]) < 0)
      Errorm("close asyncSocks");
}


// Wake up RdmaAsync thread if it is in poll
void RdmaAsync::wakeUp()
{
  int rc;
  char buf[1] = {'x'};
  while (true)
  {
    rc = send(asyncSocks[1], buf, 1, 0);
    if (rc == 0)
      Error("asyncSocks disconnected");
    if (rc > 0 || errno == EAGAIN || errno == EWOULDBLOCK)
      break;
    if (errno != EINTR)
      Errorm("send to asyncSocks");
  }
}


// RDMA async event handler thread body.  One thread handles all devices.
int RdmaAsync::threadBody()
{
  int fd, numfd, flags;
  unsigned int lastDevCount, ndx;
  RdmaDevice *rdevP;
  ibv_async_event event;
  ostringstream os;
  vector<RdmaDevice *>::iterator rdi;
  vector<RdmaDevice *> rdevList;
  struct pollfd pfd;
  vector<struct pollfd> fdList;

  lastDevCount = UINT_MAX;
  while (rdmaAsyncState == tsRun)
  {
    // If device table size changes, rebuild the poll list
    if (rdmaDevTab.size() != lastDevCount)
    {
      rdevList.reserve(rdmaDevTab.size());
      fdList.reserve(rdmaDevTab.size());
      pfd.events = POLLIN;
      pfd.revents = 0;
      for (rdi = rdmaDevTab.begin(); rdi != rdmaDevTab.end(); ++rdi)
      {
        if ((*rdi)->ibCC == NULL)
          continue;
        fd = (*rdi)->ibContext->async_fd;
        flags = fcntl(fd, F_GETFL);
        if (flags < 0)
          Errorm("fcntl F_GETFL");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
          Errorm("fcntl non-blocking");

        rdevList.push_back(*rdi);
        pfd.fd = fd;
        fdList.push_back(pfd);
      }

      rdevList.push_back(NULL);
      pfd.fd = asyncSocks[0];
      fdList.push_back(pfd);
    }

    // Poll for an event on one of the RDMA devices
    while (rdmaAsyncState == tsRun)
    {
      numfd = poll(fdList.data(), fdList.size(), -1);
      if (numfd >= 0)
        break;
      if (errno != EINTR)
        Errorm("poll");
    }
    if (rdmaAsyncState != tsRun)
      break;

    // Process all poll events
    for (ndx = 0; ndx < fdList.size() && numfd > 0; ndx++)
    {
      if (fdList[ndx].revents == 0)
        continue;
      numfd--;
      rdevP = rdevList[ndx];

      // If this is the socket pair, that means someone sent us a wakeup
      // notification.  Remove all data from the socket.
      if (rdevP == NULL)
      {
        if (fdList[ndx].fd != asyncSocks[0])
          Error("Null device pointer in fdList");
        char tmpBuf[16];
        while (recv(asyncSocks[0], tmpBuf, sizeof(tmpBuf), 0) > 0);
        continue;
      }

      if (ibv_get_async_event(rdevP->ibContext, &event) != 0)
        Error("ibv_get_async_event failed");

      os.str("RDMA async event ");
      os << rdmaEventToStr(event.event_type);

      switch (event.event_type)
      {
        // QP events
        case IBV_EVENT_QP_FATAL:
        case IBV_EVENT_QP_REQ_ERR:
        case IBV_EVENT_QP_ACCESS_ERR:
        case IBV_EVENT_COMM_EST:
        case IBV_EVENT_SQ_DRAINED:
        case IBV_EVENT_PATH_MIG:
        case IBV_EVENT_PATH_MIG_ERR:
        case IBV_EVENT_QP_LAST_WQE_REACHED:
          os << " on QP " << event.element.qp;
          break;

        // CQ events
        case IBV_EVENT_CQ_ERR:
          os << " on CQ " << event.element.cq;
          break;

        // SRQ events
        case IBV_EVENT_SRQ_ERR:
        case IBV_EVENT_SRQ_LIMIT_REACHED:
          os << " on SRQ " << event.element.srq;
          break;

        // Port events
        case IBV_EVENT_PORT_ACTIVE:
        case IBV_EVENT_PORT_ERR:
        case IBV_EVENT_LID_CHANGE:
        case IBV_EVENT_PKEY_CHANGE:
        case IBV_EVENT_SM_CHANGE:
        case IBV_EVENT_CLIENT_REREGISTER:
          os << " on port " << event.element.port_num;
          break;

        // CA events
        case IBV_EVENT_DEVICE_FATAL:
          break;

        default:
          break;
      }
      Warn(os.str());
      ibv_ack_async_event(&event);
    }
  }

  // Notify killThread that we are done
  thLock(&globalMutex);
  rdmaAsyncState = tsDead;
  thBcast(&globalCond);
  thUnlock(&globalMutex);

  Logt(1, "RdmaAsync thread terminated");
  return 0;
}


// RDMA connection manager event handler thread body
int RdmaCM::threadBody()
{
  rdma_cm_event *eventP;
  RdmaConn *rdcP;

  while (rdmaCMState == tsRun)
  {
    if (cmChan == NULL)
      Error("Null cmChan in rdmaCM thread");

    if (rdma_get_cm_event(cmChan, &eventP) != 0)
    {
      if (rdmaCMState != tsRun)
        break;
      Errorm("rdma_get_cm_event");
    }

    rdcP = reinterpret_cast<RdmaConn *>(eventP->id->context);
    if (rdcP == NULL)
      Error("Null connection pointer in CM event");

    Logt(3, "RDMA CM event " << rdmaCMEventToStr(eventP->event)
         << " for RdmaConn " << rdcP);

    rdcP->rdHandleCMEvent(eventP);
  }

  // Notify killThread that we are done
  thLock(&globalMutex);
  rdmaCMState = tsDead;
  thBcast(&globalCond);
  thUnlock(&globalMutex);

  Logt(1, "RdmaCM thread terminated");
  return 0;
}
#endif // RDMA


// Print help message
static void helpCmd(vector<string> *argsP)
{
  cout << "Commands:"
       << endl
       << "  help                  Print help message" << endl
       << "  quit                  Exit from program" << endl
       << "  version               Show program version" << endl
       << "  debug [LEVEL]         Set debugging output level" << endl
       << "  source FILENAME...    Read commands from file" << endl
       << "  check HOSTNAME...     Quick performance test to single nodes from local" << endl
       << "  server HOSTNAME...    Designate nodes as servers" << endl
       << "  client HOSTNAME...    Designate nodes as clients" << endl
       << "  delete HOSTNAME...    Remove server or client nodes from test" << endl
       << "  reset                 Close connections and clear node tables" << endl
       << "  status                Show status of all nodes" << endl
       << "  ttime NSEC            Set run time (in seconds) for tests" << endl
       << "  buffsize NBYTES       Set I/O data buffer size for tests" << endl
       << "  socksize NBYTES       Set size of TCP send/receive buffer space" << endl
       << "  threads NTHREADS      Set number of tester threads to use on clients" << endl
       << "                          (default " << TESTER_THREADS << ")" << endl
       << "  parallel N            Set number of parallel socket connections (default 1)" << endl
       << "  rdma [on|off|all|inline] Enable or disable RDMA for sending data blocks" << endl
       << "  maxrdma N             Set maximum number of RDMA ports to use per node" << endl
       << "  usecm [on|off]        Use Connection Manager to establish RDMA connections" << endl
       << "  sinline [on|off]      Use inline data in RDMA send" << endl
       << "  hist [on|off]         Set printing of response time histograms on or off" << endl
       << "                          (if no option given, then toggle)" << endl
       << "  verify [on|off]       Verify that contents of data messages are correct" << endl
       << "  plot [FILENAME]       Write test results in gnuplot format to specified file" << endl
       << "                          (if no filename given, then turn off plotting)" << endl
       << "  test TTYPE...         Run performance tests from clients to servers" << endl
       << "  kill HOSTNAME...      Shut down " << progname << " server on specified nodes" << endl
       << "  killall               Shut down " << progname << " on all client and server nodes" << endl
       << endl
       << "Test types:" << endl
       << "  write         Clients write round-robin to all servers" << endl
       << "  read          Clients read round-robin from all servers" << endl
       << "  nwrite        Same as write test, but use NSD-style writing" << endl
       << "  swrite        Each tester thread writes to only one server" << endl
       << "  sread         Each tester thread reads from only one server" << endl
       << "  rw            Half of the tester threads read and half write" << endl;
}


// Exit from program
static void quitCmd(vector<string> *argsP)
{
  quitflag = true;
}


// Read commands from file
static void sourceCmd(vector<string> *argsP)
{
  vector<string>::iterator arg;
  ifstream infile;
  string fname, line;

  if (argsP->empty())
  {
    Log("File name missing");
    return;
  }
  nestingLevel++;
  if (nestingLevel > 10)
  {
    Log("Nesting level too deep");
    return;
  }
  for (arg = argsP->begin(); arg != argsP->end(); ++arg)
  {
    fname = *arg;
    infile.open(fname.c_str());
    if (!infile)
    {
      Logm("open of " << fname << " failed");
      break;
    }
    while (getline(infile, line))
      splitCmd(line, &commands);
    infile.close();
  }
}


// Show program version
static void versionCmd(vector<string> *argsP)
{
  Log(version);
}


// Set debugging output level
static void debugCmd(vector<string> *argsP)
{
  if (remoteDebugLevel < 0)
    remoteDebugLevel = 0;
  if (argsP->empty())
    remoteDebugLevel++;
  else
    remoteDebugLevel = atoi((*argsP)[0].c_str());
  Log("Debugging output level set to " << remoteDebugLevel);
}


// Send current test parameters to target, and tell the target whether or
// not it is a server node.  Return true if error occurred.
static bool sendParms(Target *targP)
{
  DataBuff db(14 * sizeof(UInt32));
  db.putUInt32(testTime);
  db.putUInt32(buffsize);
  db.putUInt32(socksize);
  db.putUInt32(nTesterThreads);
  db.putUInt32(nParallel);
  db.putUInt32(useRdma);
  db.putUInt32(useCM);
  db.putUInt32(sinline);
  db.putUInt32(verify);
  db.putUInt32(clientNodes.size());
  db.putInt32(remoteDebugLevel);
  db.putInt32(maxRdma);
  db.putInt32(!targP->isClient);

  RcvMsg *rmsgP = targP->sendm(mtParms, &db);
  bool gotErr = rmsgP->showError();
  targP->remPinfo.clear();
  if (!gotErr)
  {
    Int32 n;
    for (n = rmsgP->msgBuff.getInt32(); n > 0; n--)
    {
      RdmaPortInfo pinfo;
      pinfo.getBuff(&rmsgP->msgBuff);
      targP->remPinfo.insert(pinfo);
    }
  }
  delete rmsgP;
  return gotErr;
}


// Quick single-threaded performance test to individual nodes from local
static void checkCmd(vector<string> *argsP)
{
  DataBuff db, wbuff, rbuff;
  IpAddr iaddr;
  Target *targP;
  string errmsg;
  RcvMsg *rmsgP;
  HTime startTime, endTime, lastTime;
  UInt64 totBytes;
  vector<string>::iterator arg;
  Histogram hist;
  bool gotError = false;
  list<TType> tests;
  list<TType>::iterator tt;

  if (argsP->empty())
  {
    Log("Host name missing");
    return;
  }
  if (useRdma != rOff)
  {
    Log("Check command isn't supported with RDMA enabled.");
    return;
  }

  wbuff.newBuff(buffsize);
  wbuff.fillBuff(randSeed());

  rbuff.newBuff(sizeof(UInt64) + sizeof(RdmaAddr) + sizeof(UInt32));
  rbuff.putUInt64(randSeed());
  rbuff.putRdmaAddr(RdmaAddr());
  rbuff.putUInt32(0);

  tests.push_back(ttWrite);
  tests.push_back(ttRead);

  for (arg = argsP->begin(); arg != argsP->end(); ++arg)
  {
    if (iaddr.parse(*arg) != E_OK)
      continue;
    targP = new Target(*arg, iaddr);
    errmsg = targP->makeConnection();
    if (!errmsg.empty())
    {
      Log(errmsg);
      delete targP;
      continue;
    }

    // Tell remote node the test parameters
    if (sendParms(targP))
      return;

    // Allocate memory buffers
    db.newBuff(sizeof(UInt32));
    db.putUInt32(0);
    rmsgP = targP->sendm(mtAlloc, &db);
    if (rmsgP->showError())
      gotError = true;
    delete rmsgP;
    if (gotError)
      return;

    for (tt = tests.begin(); tt != tests.end(); ++tt)
    {
      totBytes = 0;
      startTime = endTime = getTime();
      gotError = false;
      while (endTime - startTime < sectoht(testTime))
      {
        lastTime = endTime;

        if (*tt == ttWrite)
          rmsgP = targP->sendm(mtWrite, &wbuff);
        else
          rmsgP = targP->sendm(mtRead, &rbuff);
        if (rmsgP->showError())
          gotError = true;
        delete rmsgP;
        if (gotError)
          break;

        endTime = getTime();
        hist.addEntry(endTime - lastTime);
        totBytes += buffsize + MSG_HDRSIZE;
      }
      if (gotError)
      {
        delete targP;
        continue;
      }

      double elapsedT = httosec(endTime - startTime);
      double rate = siground(totBytes / elapsedT / 1000000.0, 3);
      if (*tt == ttWrite)
        Log("write rate " << rate << " MB/sec");
      else
        Log("read rate " << rate << " MB/sec");
      if (showHist)
        cout << "block transmit times (average "
             << siground(hist.average() * 1000.0, 4) << " msec, median "
             << siground(hist.median() * 1000.0, 4) << " msec)" << endl
             << "     msec  nevents" << endl
             << hist;
    }

    // Free memory buffers
    rmsgP = targP->sendm(mtFree, NULL);
    rmsgP->showError();
    delete targP;
  }
}


// Close connections and clear node tables
static void resetCmd(vector<string> *argsP)
{
  map<IpAddr, Target *>::iterator node;

  // Tell every node that we know about to close any connections that
  // it has, and then remove the node from local tables.
  for (node = allNodes.begin(); node != allNodes.end(); )
  {
    Target *targP = node->second;
    RcvMsg *rmsgP = targP->sendm(mtReset);
    rmsgP->showError();
    delete rmsgP;
    delete targP;
    allNodes.erase(node++);
  }
  serverNodes.clear();
  clientNodes.clear();
}


// Shut down all client and server nodes
static void killallCmd(vector<string> *argsP)
{
  map<IpAddr, Target *>::iterator node;
  for (node = allNodes.begin(); node != allNodes.end(); )
  {
    Target *targP = node->second;
    delete targP->sendm(mtKill);
    delete targP;
    allNodes.erase(node++);
  }
  serverNodes.clear();
  clientNodes.clear();
}


// Shut down server on specified nodes
static void killCmd(vector<string> *argsP)
{
  IpAddr iaddr;
  Target *targP;
  string errmsg;
  vector<string>::iterator arg;

  if (argsP->empty())
  {
    Log("Host name missing");
    return;
  }
  for (arg = argsP->begin(); arg != argsP->end(); ++arg)
  {
    if (iaddr.parse(*arg) != E_OK)
      continue;
    targP = new Target(*arg, iaddr);
    errmsg = targP->makeConnection();
    if (!errmsg.empty())
      Log("Cannot connect to " << *arg << ": " << errmsg);
    else
      delete targP->sendm(mtKill);
    delete targP;
  }
}


// Common routine for serverCmd and clientCmd
static void doClientServer(vector<string> *argsP, list<Target *> *targListP)
{
  string hname, errmsg;
  IpAddr iaddr;
  Target *targP;
  vector<string>::iterator arg;

  if (argsP->empty())
  {
    Log("Host name missing");
    return;
  }
  for (arg = argsP->begin(); arg != argsP->end(); ++arg)
  {
    hname = *arg;
    if (iaddr.parse(hname) != E_OK)
      continue;
    if (allNodes.find(iaddr) != allNodes.end())
    {
      Log(hostString(hname, iaddr) << " is already in use");
      continue;
    }
    targP = new Target(hname, iaddr);
    errmsg = targP->makeConnection();
    if (!errmsg.empty())
    {
      Log("Cannot connect to " << hname << ": " << errmsg);
      delete targP;
    }
    else
      targListP->push_back(targP);
  }
}


// Designate nodes as servers
static void serverCmd(vector<string> *argsP)
{
  list<Target *> targList;
  doClientServer(argsP, &targList);

  list<Target *>::const_iterator targ;
  for (targ = targList.begin(); targ != targList.end(); ++targ)
  {
    serverNodes.insert(pair<IpAddr, Target *>((*targ)->iaddr, *targ));
    allNodes[(*targ)->iaddr] = *targ;
  }
}


// Designate nodes as clients
static void clientCmd(vector<string> *argsP)
{
  list<Target *> targList;
  doClientServer(argsP, &targList);

  list<Target *>::const_iterator targ;
  for (targ = targList.begin(); targ != targList.end(); ++targ)
  {
    (*targ)->isClient = true;
    clientNodes[(*targ)->iaddr] = *targ;
    allNodes[(*targ)->iaddr] = *targ;
  }
}


// Remove server or client nodes from test
static void deleteCmd(vector<string> *argsP)
{
  string hname;
  IpAddr iaddr;
  Target *targP;
  vector<string>::iterator arg;
  map<IpAddr, Target *>::iterator node;

  if (argsP->empty())
  {
    Log("Host name missing");
    return;
  }
  for (arg = argsP->begin(); arg != argsP->end(); ++arg)
  {
    hname = *arg;
    if (iaddr.parse(hname) != E_OK)
      return;
    node = allNodes.find(iaddr);
    if (node == allNodes.end())
    {
      Log(hostString(hname, iaddr) << " not found");
      continue;
    }
    targP = node->second;

    // Don't worry if send fails.  If we ever use this node again, we'll
    // send another mtReset and check results from that.
    if (targP->connP != NULL)
      delete targP->sendm(mtReset);

    delete targP;
    allNodes.erase(node);
    serverNodes.erase(iaddr);
    clientNodes.erase(iaddr);
  }
}


// Show status of a target
static void showStatus(pair<IpAddr, Target *> p)
{
  Target *targP = p.second;
  cout << "  " << targP->name();
  if (targP->connP == NULL)
  {
    cout << ", not connected" << endl;
    return;
  }

  RcvMsg *rmsgP = targP->sendm(mtStatus);
  if (!rmsgP->errText.empty())
    cout << endl << "    " << rmsgP->errText << endl;
  else
    cout << rmsgP->msgBuff.getString();
  delete rmsgP;
}


// If the TCP connection for this target is not connected, try to reconnect it
static void reconnect(pair<IpAddr, Target *> p)
{
  Target *targP = p.second;
  if (targP->connP != NULL)
  {
    if (!targP->connP->isBroken())
      return;
    targP->connP->connShutdown();
    targP->connP->releaseConn();
    targP->connP = NULL;
  }
  (void) targP->makeConnection();
}


// Show status of all nodes
static void statusCmd(vector<string> *argsP)
{
  string r;
  switch (useRdma)
  {
    case rOff:    r = "no";     break;
    case rOn:     r = "yes";    break;
    case rAll:    r = "all";    break;
    case rInline: r = "inline"; break;
  }
  if (useRdma != rOff && useCM)
    r += ", CM";
  string v = verify ? "on" : "off";
  cout << "test time: " << testTime << " sec" << endl
       << "data buffer size: " << buffsize << endl
       << "TCP socket send/receive buffer size: " << socksize << endl
       << "tester threads: " << nTesterThreads << endl
       << "parallel connections: " << nParallel << endl
       << "RDMA enabled: " << r << endl;
  if (maxRdma != MAXRDMA_UNLIMITED)
    cout << "max RDMA ports: " << maxRdma << endl;
  if (remoteDebugLevel >= 0)
    cout << "debug level: " << remoteDebugLevel << endl;
  cout << endl;

  if (!clientNodes.empty())
  {
    cout << "clients:" << endl;
    for_each(clientNodes.begin(), clientNodes.end(), reconnect);
    for_each(clientNodes.begin(), clientNodes.end(), showStatus);
  }
  if (!serverNodes.empty())
  {
    cout << "servers:" << endl;
    for_each(serverNodes.begin(), serverNodes.end(), reconnect);
    for_each(serverNodes.begin(), serverNodes.end(), showStatus);
  }
}


// Set run time for tests
static void ttimeCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    Log("Number of seconds argument missing");
    return;
  }
  testTime = atoi((*argsP)[0].c_str());
  if (testTime < 1)
    testTime = 1;
  Log("Test time set to " << testTime << " seconds");
}


// Set buffer size for tests
static void buffsizeCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    Log("Buffer size argument missing");
    return;
  }
  buffsize = atoi((*argsP)[0].c_str());
  if (buffsize < MIN_BUFFSIZE) buffsize = MIN_BUFFSIZE;
  if (buffsize > MAX_BUFFSIZE) buffsize = MAX_BUFFSIZE;
  Log("Buffer size set to " << buffsize << " bytes");
}


// Set size of TCP send/receive buffer space
static void socksizeCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    Log("Size argument missing");
    return;
  }
  socksize = atoi((*argsP)[0].c_str());
  if (socksize < 0) socksize = 0;
  if (socksize > MAX_SOCKSIZE) socksize = MAX_SOCKSIZE;
  Log("TCP send/receive buffer size set to " << socksize << " bytes");
}


// Set number of tester threads to use on clients
static void threadsCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    Log("Number of threads argument missing");
    return;
  }
  nTesterThreads = atoi((*argsP)[0].c_str());
  if (nTesterThreads < 1)   nTesterThreads = 1;
  if (nTesterThreads > MAX_TESTERS) nTesterThreads = MAX_TESTERS;
  Log("Number of tester threads set to " << nTesterThreads);
}


// Tell clients to connect to servers
static Errno doConnect()
{
  Errno err = E_OK;
  map<IpAddr, Target *>::const_iterator node;
  multimap<IpAddr, Target *>::const_iterator snode;
  MsgRecord mr;
  RcvMsg *rmsgP;
  Target *targP;
  DataBuff db;
  bool gotError;

  if (serverNodes.empty())
  {
    Log("No server nodes found");
    return E_INVAL;
  }
  if (clientNodes.empty())
  {
    Log("No client nodes found");
    return E_INVAL;
  }

  // Tell the server nodes to close any connections that they might have
  // had from previous sessions, where they were clients.
  for (snode = serverNodes.begin(); snode != serverNodes.end(); ++snode)
    if (snode->second->connP->sendMessage(mtReset, NULL, &mr) != E_OK)
    {
      Log("Send to " << snode->second->hostname << " failed");
      err = E_SENDFAILED;
    }
  if (mr.checkReplies())
    return E_REPLY;
  if (err != E_OK)
    return err;

  // Make a list of all of the servers to send to the clients
  unsigned int len = sizeof(UInt32);
  set<RdmaPortInfo>::const_iterator pi;
  for (snode = serverNodes.begin(); snode != serverNodes.end(); ++snode)
  {
    targP = snode->second;
    len += calcLen(targP->hostname) + targP->iaddr.getSize() + sizeof(Int32);
    for (pi = targP->remPinfo.begin(); pi != targP->remPinfo.end(); ++pi)
      len += (*pi).calcPortInfoLen();
  }
  db.newBuff(len);
  db.putUInt32(serverNodes.size());
  for (snode = serverNodes.begin(); snode != serverNodes.end(); ++snode)
  {
    targP = snode->second;
    db.putString(targP->hostname);
    db.putIpAddr(targP->iaddr);
    db.putInt32(targP->remPinfo.size());
    for (pi = targP->remPinfo.begin(); pi != targP->remPinfo.end(); ++pi)
      (*pi).putBuff(&db);
  }

  // Send the server list to all clients
  gotError = false;
  for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
  {
    Target *targP = node->second;
    if (targP->connP->sendMessage(mtConnect, &db, &mr) != E_OK)
    {
      Log("Send to " << targP->hostname << " failed");
      gotError = true;
    }
    else
      targP->didConnect = true;
  }
  mr.waitForReplies();

  while (true)
  {
    rmsgP = mr.nextReply();
    if (rmsgP == NULL)
      break;
    if (rmsgP->showError())
      gotError = true;
    else
      Logt(1, rmsgP->connP->destName() << " connected");
    delete rmsgP;
  }
  return gotError ? E_CONNFAILED : E_OK;
}


// Run performance test from clients to servers
static void testCmd(vector<string> *argsP)
{
  vector<string>::iterator arg;
  map<IpAddr, Target *>::iterator node;
  multimap<IpAddr, Target *>::const_iterator snode;
  list<TType> tests;
  list<TType>::iterator tt;
  MsgRecord mr, mrstat;
  HTime startTime, endTime, runTime, totTime;
  RcvMsg *rmsgP = NULL;
  Target *targP;
  DataBuff db;
  bool gotIdle, gotError;
  UInt32 idlePct, totMsgs;
  UInt64 totBytes, clientIdle, serverIdle;
  Histogram *hP;
  ofstream plfile;
  bool plotOpened = false;

  if (argsP->empty())
  {
    tests.push_back(ttNwrite);
    tests.push_back(ttRead);
  }
  else
  {
    for (arg = argsP->begin(); arg != argsP->end(); ++arg)
    {
      if (match("write", *arg))
        tests.push_back(ttWrite);
      else if (match("read", *arg))
        tests.push_back(ttRead);
      else if (match("nwrite", *arg))
        tests.push_back(ttNwrite);
      else if (match("rw", *arg))
      {
        if (nTesterThreads < 2)
        {
          Log("Need at least two tester threads for rw test");
          return;
        }
        tests.push_back(ttRW);
      }
      else if (match("swrite", *arg))
        tests.push_back(ttSwrite);
      else if (match("sread", *arg))
        tests.push_back(ttSread);
      else
      {
        Log("Invalid test type: " << *arg);
        Log("Valid types are: write nwrite read rw swrite sread");
        return;
      }
    }
  }

  if (clientNodes.empty())
  {
    Log("No client nodes found");
    return;
  }
  for_each(allNodes.begin(), allNodes.end(), reconnect);
  for (node = allNodes.begin(); node != allNodes.end(); ++node)
  {
    targP = node->second;
    if (targP->connP == NULL)
    {
      Log(targP->name() << " is not connected");
      return;
    }
    targP->didAlloc = targP->didConnect = false;
  }

  // Tell everyone the current test parameters.  Find out what RDMA
  // devices each target has.
  gotError = false;
  for (node = allNodes.begin(); node != allNodes.end(); ++node)
    if (sendParms(node->second))
      gotError = true;
  if (gotError)
    return;

  // Allocate memory buffers.  This could be done at connect time, but it
  // is more convenient to send out the requests here from the admin node
  // since the buffer pool size depends on the number of nodes and RDMA
  // ports, which are only known here.
  db.newBuff(sizeof(Int32));
  for (node = allNodes.begin(); node != allNodes.end(); ++node)
  {
    targP = node->second;
    db.resetBuff();
    db.putInt32(targP->calcConnectionCount());
    if (targP->connP->sendMessage(mtAlloc, &db, &mr) != E_OK)
      Log("Send to " << targP->name() << " failed");
    else
      targP->didAlloc = true;
  }
  if (mr.checkReplies())
    goto exit;

  // Pass list of servers to all clients and have them connect
  if (doConnect() != E_OK)
    goto exit;

  if (!plotFname.empty())
  {
    plfile.open(plotFname.c_str());
    if (!plfile)
    {
      Logm("open of " << plotFname << " failed");
      goto exit;
    }
    plotOpened = true;
  }

  db.newBuff(sizeof(UInt32));
  for (tt = tests.begin(); tt != tests.end(); ++tt)
  {
    startTime = getTime();
    runTime = sectoht(testTime);

    // Tell all clients to start the test, but don't start collecting
    // statistics yet.
    db.resetBuff();
    db.putUInt32(*tt);

    for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
      if (node->second->connP->sendMessage(mtTest, &db, &mr) != E_OK)
      {
        Log("Send to " << node->second->name() << " failed");
        goto exit;
      }

    // Delay for 10% of test time and then tell all nodes to start
    // gathering statistics.
    totTime = sleepUntil(startTime + runTime/10);
    for (node = allNodes.begin(); node != allNodes.end(); ++node)
    {
      targP = node->second;
      if (targP->connP->sendMessage(mtStatOn, NULL, &mrstat) != E_OK)
      {
        Log("Send to " << targP->name() << " failed");
        goto exit;
      }
    }
    if (mrstat.checkReplies())
      goto exit;

    // Stop gathering statistics after 90% of test time.  Verify that we
    // didn't use all of the test time getting started.  We need at least
    // 100 msec left over to run the test
    endTime = startTime + runTime - runTime/10;
    if (httomsec(endTime - getTime()) < 100)
    {
      Log("Test startup took too long");
      goto exit;
    }
    sleepUntil(endTime);
    for (node = allNodes.begin(); node != allNodes.end(); ++node)
    {
      targP = node->second;
      if (targP->connP->sendMessage(mtStatOff, NULL, &mrstat) != E_OK)
      {
        Log("Send to " << targP->name() << " failed");
        goto exit;
      }
    }
    if (mrstat.checkReplies())
      goto exit;
    totTime = getTime() - totTime;

    // Wait for all clients to finish testing
    mr.waitForReplies();

    // Add up test results
    totBytes = totMsgs = clientIdle = 0;
    gotIdle = true;
    while (true)
    {
      rmsgP = mr.nextReply();
      if (rmsgP == NULL)
        break;
      if (rmsgP->showError())
        goto exit;

      totBytes += rmsgP->msgBuff.getUInt64();
      idlePct = rmsgP->msgBuff.getUInt32();
      if (idlePct <= 100)
        clientIdle += idlePct;
      else
        gotIdle = false;
      rmsgP->connP->getHistP()->getBuff(&rmsgP->msgBuff);
      rmsgP->connP->getLatP()->getBuff(&rmsgP->msgBuff);
      totMsgs += rmsgP->connP->getHistP()->getNevents();
      delete rmsgP;
    }

    // Gather server CPU idle percentage
    multimap<IpAddr, Target *>::const_iterator snode;
    for (snode = serverNodes.begin(); snode != serverNodes.end(); ++snode)
      if (snode->second->connP->sendMessage(mtIdlePct, NULL, &mr) != E_OK)
      {
        Log("Send to " << snode->second->name() << " failed");
        goto exit;
      }
    mr.waitForReplies();

    serverIdle = 0;
    while (true)
    {
      rmsgP = mr.nextReply();
      if (rmsgP == NULL)
        break;
      if (rmsgP->showError())
        goto exit;

      idlePct = rmsgP->msgBuff.getUInt32();
      if (idlePct <= 100)
        serverIdle += idlePct;
      else
        gotIdle = false;
      delete rmsgP;
    }

    // Print results
    cout << clientNodes.size() << "-" << serverNodes.size() << " ";
    switch (*tt)
    {
      case ttWrite:  cout << "write";  break;
      case ttNwrite: cout << "nwrite"; break;
      case ttRead:   cout << "read";   break;
      case ttRW:     cout << "rw";     break;
      case ttSwrite: cout << "swrite"; break;
      case ttSread:  cout << "sread";  break;
      default:       Error("invalid test type"); break;
    }
    double elapsedT = httosec(totTime);
    double rate = siground(totBytes / elapsedT / 1000000.0, 3);
    double mrate = siground(totMsgs / elapsedT, 3);
    cout << " " << rate << " MB/sec";
    cout << " (" << mrate << " msg/sec)";
    if (gotIdle)
    {
      cout << ", cli " << 100 - clientIdle / clientNodes.size() << "%";
      cout << " srv " << 100 - serverIdle / serverNodes.size() << "%";
    }
    cout << ", time " << testTime << ", buff " << buffsize;
    if (socksize != 0)
      cout << ", sock " << socksize;
    if (nTesterThreads != TESTER_THREADS)
      cout << ", th " << nTesterThreads;
    if (nParallel > 1)
      cout << ", parallel " << nParallel;
    if (useRdma != rOff)
      cout << ", RDMA";
    if (useRdma == rAll)
      cout << " all";
    else if (useRdma == rInline)
      cout << " inline";
    if (maxRdma != MAXRDMA_UNLIMITED)
      cout << ", maxrdma " << maxRdma;
    if (verify)
      cout << ", verify";
    if (sinline)
      cout << ", sinline";
    cout << endl;

	cout << endl;
	for (node = clientNodes.begin(); node != clientNodes.end(); ++node) {
	  Histogram *lP = node->second->connP->getLatP();
	  cout << node->second->hostname << " network delay times (average "
           << lP->average() * 1000.0 << " msec, median "
           << lP->median() * 1000.0 << " msec, std deviation "
           << lP->standardDeviation() * 1000.0 << " msec)" << endl
           << "     msec  nevents" << endl
		   << *lP << endl;
	}

    if (showHist)
    {
      cout << endl;
      for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
      {
        Histogram *hP = node->second->connP->getHistP();
        cout << node->second->hostname << " block transmit times (average "
             << siground(hP->average() * 1000.0, 4) << " msec, median "
             << siground(hP->median() * 1000.0, 4) << " msec)" << endl
             << "     msec  nevents" << endl
             << *hP << endl;
      }
    }

    if (!plotFname.empty())
    {
      unsigned int n = clientNodes.size();
      if (n > 1)
      {
        int rows, cols;
        rows = (n + 3) / 4;
        cols = n > 4 ? 4 : n;
        plfile << "set multiplot layout " << rows << "," << cols
               << " title \"Block transmit times (msec)\"" << endl
               << "set xlabel" << endl
               << "set ylabel" << endl;
      }
      else
        plfile << "set xlabel \"Time (msec)\"" << endl
               << "set ylabel" << endl;

      plfile << "set format y \"\"" << endl
             << "set style data boxes" << endl
             << "set style fill solid" << endl
             << "set boxwidth 0.9" << endl
             << "unset key" << endl
             << "set border 1" << endl
             << "set xtics out nomirror offset 0,0.5" << endl
             << "unset ytics" << endl;

      // Compute bounds for all nodes and use that to set xrange and yrange
      // so that all plots will have the same scale.
      UInt32 v, maxval = 0;
      double t, minT = 9999999999999999.0, maxT = 0.0;
      for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
      {
        hP = node->second->connP->getHistP();
        v = hP->maxBucket(); if (v > maxval) maxval = v;
        t = hP->minTime();   if (t < minT)   minT = t;
        t = hP->maxTime();   if (t > maxT)   maxT = t;
      }

      // Convert time bounds to next msec
      minT *= 1000.0;
      maxT *= 1000.0;
      minT = (minT < 1) ? 0 : floor(minT - 1);
      maxT = floor(maxT + 1);
      maxval = (maxval + 9) / 10 * 10;

      plfile << "set xrange [" << minT << ":" << maxT << "]" << endl
             << "set yrange [0:" << maxval << "]" << endl;

      for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
      {
        hP = node->second->connP->getHistP();
        plfile << "set label \"" << node->second->hostname << "\""
               << " at graph 0.5,0.8 center" << endl
               << "plot '-' using 1:2" << endl
               << *hP << "e" << endl
               << "unset label" << endl;
      }
      if (clientNodes.size() > 1)
        plfile << "unset multiplot" << endl;

      plfile << "pause mouse any keypress" << endl;
    }
  }

exit:
  if (plotOpened)
  {
    plfile.close();
    if (!plfile)
      Logm("close of " << plotFname << " failed");
  }

  // If we broke out early due to an error, clean out any outstanding
  // replies.
  delete rmsgP;
  mrstat.checkReplies();
  mr.checkReplies();

  // Shut down RDMA connections
  if (useRdma != rOff)
  {
    for (node = clientNodes.begin(); node != clientNodes.end(); ++node)
    {
      targP = node->second;
      if (targP->didConnect &&
          targP->connP->sendMessage(mtRdmaDone, NULL, &mr) != E_OK)
        Log("Send to " << targP->name() << " failed");
    }
    mr.checkReplies();
  }

  // Free memory buffers
  for (node = allNodes.begin(); node != allNodes.end(); ++node)
  {
    targP = node->second;
    if (targP->didAlloc &&
        targP->connP->sendMessage(mtFree, NULL, &mr) != E_OK)
      Log("Send to " << targP->name() << " failed");
  }
  mr.checkReplies();
}


// Toggle printing of client resonse time histograms
static void histCmd(vector<string> *argsP)
{
  if (argsP->empty())
    showHist = !showHist;
  else if ((*argsP)[0] == "on")
    showHist = true;
  else if ((*argsP)[0] == "off")
    showHist = false;
  else
  {
    Log("Invalid option");
    return;
  }
  cout << "Histogram printing is now ";
  if (showHist) cout << "on"; else cout << "off";
  cout << endl;
}


// Set number of parallel socket connections
static void parallelCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    Log("Number of connections argument is missing");
    return;
  }
  nParallel = atoi((*argsP)[0].c_str());
  if (nParallel < 1) nParallel = 1;
  if (nParallel > MAX_PARALLEL) nParallel = MAX_PARALLEL;
  Log("Number of parallel socket connections set to " << nParallel);
}


// Use RDMA for sending data blocks
static void rdmaCmd(vector<string> *argsP)
{
#ifdef RDMA
  if (argsP->empty())
    useRdma = (useRdma != rOff) ? rOff : rOn;
  else if ((*argsP)[0] == "on")
    useRdma = rOn;
  else if ((*argsP)[0] == "off")
    useRdma = rOff;
  else if (match("all",(*argsP)[0]))
    useRdma = rAll;
  else if (match("inline", (*argsP)[0]))
    useRdma = rInline;
  else
  {
    Log("Invalid option");
    return;
  }
  string r;
  switch (useRdma)
  {
    case rOff:    r = "off";       break;
    case rOn:     r = "on";        break;
    case rAll:    r = "on all";    break;
    case rInline: r = "on inline"; break;
  }
  cout << "RDMA is now " << r << endl;
#else
  Log("RDMA is not supported");
#endif
}


// Specify maximum number of RDMA ports to use
static void maxrdmaCmd(vector<string> *argsP)
{
  maxRdma = argsP->empty() ? MAXRDMA_UNLIMITED : atoi((*argsP)[0].c_str());
  if (maxRdma <= 0) maxRdma = MAXRDMA_UNLIMITED;
  cout << "Maximum number of RDMA ports is now ";
  if (maxRdma == MAXRDMA_UNLIMITED)
    cout << "unlimited" << endl;
  else
    cout << maxRdma << endl;
}


// Toggle use of Connection Manager
static void usecmCmd(vector<string> *argsP)
{
  if (argsP->empty())
    useCM = !useCM;
  else if ((*argsP)[0] == "on")
    useCM = true;
  else if ((*argsP)[0] == "off")
    useCM = false;
  else
  {
    Log("Invalid option");
    return;
  }
  cout << "Connection Manager is now ";
  if (useCM) cout << "enabled"; else cout << "disabled";
  cout << endl;
}


// Use inline data in RDMA send
static void sinlineCmd(vector<string> *argsP)
{
  if (argsP->empty())
    sinline = !sinline;
  else if ((*argsP)[0] == "on")
    sinline = true;
  else if ((*argsP)[0] == "off")
    sinline = false;
  else
  {
    Log("Invalid option");
    return;
  }
  cout << "Inline sends are now ";
  if (sinline) cout << "on"; else cout << "off";
  cout << endl;
}


// Toggle verification of data message contents
static void verifyCmd(vector<string> *argsP)
{
  if (argsP->empty())
    verify = !verify;
  else if ((*argsP)[0] == "on")
    verify = true;
  else if ((*argsP)[0] == "off")
    verify = false;
  else
  {
    Log("Invalid option");
    return;
  }
  cout << "Message verification is now ";
  if (verify) cout << "on"; else cout << "off";
  cout << endl;
}


// Write test results in gnuplot format to specified file
static void plotCmd(vector<string> *argsP)
{
  if (argsP->empty())
  {
    plotFname.clear();
    Log("Plotting disabled");
    return;
  }
  plotFname = (*argsP)[0];
  Log("Plot commands will be written to " << plotFname);
}


// Entry in command table
struct Command
{
  string cmd;                                   // Command keyword
  string::size_type minlen;                     // Minium abbreviation
  void (*cmdRtnP)(vector<string> *argsP);       // Routine to call
};


// Valid commands
static const Command cmdTable[] =
{
  { "hist",     2, histCmd },
  { "help",     1, helpCmd },
  { "?",        1, helpCmd },
  { "quit",     1, quitCmd },
  { "source",   2, sourceCmd },
  { ".",        1, sourceCmd },
  { "version",  1, versionCmd },
  { "debug",    3, debugCmd },
  { "check",    2, checkCmd },
  { "reset",    1, resetCmd },
  { "killall",  5, killallCmd },
  { "ka",       2, killallCmd },
  { "kill",     1, killCmd },
  { "status",   2, statusCmd },
  { "socksize", 2, socksizeCmd },
  { "server",   1, serverCmd },
  { "client",   1, clientCmd },
  { "delete",   1, deleteCmd },
  { "threads",  2, threadsCmd },
  { "ttime",    2, ttimeCmd },
  { "plot",     1, plotCmd },
  { "parallel", 2, parallelCmd },
  { "rdma",     2, rdmaCmd },
  { "maxrdma",  1, maxrdmaCmd },
  { "usecm",    1, usecmCmd },
  { "sinline",  2, sinlineCmd },
  { "verify",   4, verifyCmd },
  { "test",     1, testCmd },
  { "buffsize", 1, buffsizeCmd },
};
static const int nCommands = sizeof(cmdTable) / sizeof(struct Command);


// Handle SIGUSR1
static void sigusr1Handler(int signum)
{ }


// Handle out of memory error
static void exhausted()
{
  cerr << "Out of storage!" << endl;
  exit(EXIT_FAILURE);
}


// Print usage message and exit
static void usage()
{
  cerr << "usage:  " << progname
       << " [-d] [-h] [-i FNAME] [-p PORT] [-r RDMAPORTS] [-t NRCV] [-s]" << endl
       << "                [-w NWORKERS] [-6] [CMD...]" << endl
       << endl
       << "Options:" << endl
       << "  -d            Include debug output" << endl
       << "  -h            Print help message" << endl
       << "  -i FNAME      Read commands from file FNAME" << endl
       << "  -m PATH_MTU   The QP path_mtu value of 256, 512, 1024, 2048, 4096, or 8192" << endl
       << "                Must be supported by the device port (default is 2048)" << endl
       << "                Must be set on both client and server when starting nsdperf" << endl
       << "  -M MAXSEND    Max server RDMA read and write send size in bytes" << endl
       << "                This option emulates Spectrum Scale \"verbsRdmaMaxSendBytes\" option" << endl
       << "  -S MAXSGE     Max server RDMA read and write sge entries" << endl
       << "                This option emulates Spectrum Scale verbsRdmaMaxSge option" << endl
       << "  -p PORT       TCP port to use (default " << NSDPERF_PORT << ")" << endl
       << "  -r RDMAPORTS  RDMA devices and ports to use (default first device, port 1)" << endl
       << "  -t NRCV       Number of receiver threads (default nCPUs, min 2)" << endl
       << "  -s            Act as a server" << endl
       << "  -w NWORKERS   Number of message worker threads (default " << MSG_WORKERS << ")" << endl
       << "  -6            Use IPv6 rather than IPv4" << endl;

  exit(EXIT_FAILURE);
}


// Start of main program
int main(int argc, char *argvP[])
{
  int j, c, b;
  string::size_type spos;
  string line;

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // Trap out-of-memory errors
  set_new_handler(exhausted);

  // Get the name of this program for error messages
  progname = argvP[0];
  spos = progname.find_last_of("/\\");
  if (spos != string::npos) progname = progname.substr(spos+1);

  // Initialize logMutex now since Error macros need it
  if (pthread_mutex_init(&logMutex, NULL) != 0)
  {
    cerr << progname << ": pthread_mutex_init: " << endl;
    exit(EXIT_FAILURE);
  }

  // Figure out the endian-ness of this machine
  union { UInt16 n; UChar c[2]; } endTest;
  endTest.n = 1;
  littleEndian = (endTest.c[0] == 1);

  // Get page size of this machine
  pagesize = sysconf(_SC_PAGE_SIZE);

  // Parse options
  string fname, rdport;
  int nReceivers = numProcessors();
  while ((c = getopt(argc, argvP, "DL:M:S:dhi:m:p:r:t:sw:6")) != EOF)
    switch (c)
    {
      case 'D':                 // printf debug for RDMA
#ifdef RDMA
        rdmaDebugLevel++;
#endif
        break;

      case 'd':                 // Include debug output
        debugLevel++;
        break;

      case 'h':                 // Ask for help
        usage();
        break;

      case 'i':                 // Input file name
        fname = optarg;
        break;

      case 'L':
#ifdef RDMA
        serviceLevel = atoi(optarg);
#endif
        break;

      case 'm':                 // RDMA path_mtu
#ifdef RDMA
        path_mtu_value = atoi(optarg);
        switch (path_mtu_value)
        {
          case 256:
            path_mtu = IBV_MTU_256;
            break;
          case 512:
            path_mtu = IBV_MTU_512;
            break;
          case 1024:
            path_mtu = IBV_MTU_1024;
            break;
          case 2048:
            path_mtu = IBV_MTU_2048;
            break;
          case 4096:
            path_mtu = IBV_MTU_4096;
            break;
          case 8192:
            path_mtu = IBV_MTU_8192;
            break;
          default:
            Error("the value for -m path_mtu must be supported by the device port and be one of 256, 512, 1024, 2048, 4096, or 8192");
            exit(EXIT_FAILURE);
            break;
        }
#endif
        break;

      case 'M':                 // RDMA server max send bytes (verbsRdmaMaxSendBytes)
#ifdef RDMA
        GlobalVerbs.VerbsRdmaMaxSendBytes = atoi(optarg);
        if (GlobalVerbs.VerbsRdmaMaxSendBytes < MIN_BUFFSIZE || GlobalVerbs.VerbsRdmaMaxSendBytes > MAX_BUFFSIZE)
        {
          Error("the value for -M max_send_bytes must be >= 4096 && <= 16777216");
          exit(EXIT_FAILURE);
        }
        setMaxSend = true;
#endif
        break;

      case 'p':                 // Port to use
        port = atoi(optarg);
        break;

      case 'r':                 // RDMA devices and ports
        parseRdmaPortsOpt(optarg);
        break;

      case 't':                 // Number of receiver threads
        nReceivers = atoi(optarg);
        break;

      case 's':                 // Run in server mode
        server = true;
        break;

      case 'S':                 // RDMA server max sge (verbsRdmaMaxSendSge)
#ifdef RDMA
        GlobalVerbs.VerbsMaxSendSge = atoi(optarg);
        if (GlobalVerbs.VerbsMaxSendSge < MIN_VERBS_SEND_SGE || GlobalVerbs.VerbsMaxSendSge > MAX_VERBS_SEND_SGE)
        {
          Error("the value for -S max_send_sge must be >= 1 && <= 128");
          exit(EXIT_FAILURE);
        }
        setBuffSize = true;
#endif
        break;

      case 'w':                 // Number of message worker threads
        nWorkers = atoi(optarg);
        break;

      case '6':                 // Use IPv6 rather than IPv4
        useipv6 = true;
        break;

      default:
        exit(EXIT_FAILURE);
        break;
    }

#ifdef IPV6_SUPPORT
  addrFamily = useipv6 ? AF_INET6 : AF_INET;
#else
  if (useipv6) Error("IPv6 not supported on this system");
  addrFamily = AF_INET;
#endif
  if (nReceivers < 2) nReceivers = 2;
  if (nReceivers > 32) nReceivers = 32;
  srandom(12345);
  initClock();
  for (b = 0; b < nRtBuckets; b++)
    thInitMutex(&pendReplyTab[b].bucketMutex);

  // If input file name was given, read file contents into line buffer
  if (!fname.empty())
  {
    ifstream infile;
    infile.open(fname.c_str());
    if (!infile)
      Errorm("open of " << fname << " failed");
    while (getline(infile, line))
      splitCmd(line, &commands);
    infile.close();
  }

  // Remaining arguments are treated as a command line
  for (j = optind; j < argc; j++)
  {
    if (!line.empty())
      line += " ";
    line += argvP[j];
  }
  splitCmd(line, &commands);

  // Set up a signal handler for SIGUSR1
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1Handler;
  sa.sa_flags = 0;
  if (sigaction(SIGUSR1, &sa, NULL) < 0) Errorm("sigaction");

  // Start up threads
  thInitMutex(&globalMutex);
  thInitCond(&globalCond);
  receiverRun = true;
  for (j = 0; j < nReceivers; j++)
  {
    Receiver *rcvP = new Receiver;
    rcvP->init();
    receiverTab.push_back(rcvP);
  }
  nextReceiver = receiverTab.begin();
  thInitMutex(&workerMutex);
  thInitCond(&workerCond);
  for (j = 0; j < nWorkers; j++)
  {
    MsgWorker *mwP = new MsgWorker();
    mwP->init();
    workerTab.push_back(mwP);
  }

  thInitMutex(&testerMutex);
  thInitCond(&testerCond);

  if (server)
  {
    laThreadP = new ListenAccept;
    laThreadP->init();
    Logt(1, progname << " " << version << " server started");
    waitForThreads();
#ifdef RDMA
    rdmaShutdown();
#endif
    exit(EXIT_SUCCESS);
  }

  // Read commands
  bool interactive = isatty(fileno(stdin));
  while (true)
  {
    // If no more pre-read lines, prompt for a new one
    while (commands.empty())
    {
      nestingLevel = 0;
      if (interactive)
        cout << progname << "> ";
      if (!getline(cin, line))
      {
        if (interactive)
          cout << endl;
        quitflag = true;
        break;
      }
      splitCmd(line, &commands);
    }
    if (quitflag)
      break;

    line = commands.front();
    commands.pop_front();

    // First word in line is command name
    spos = 0;
    string cmd = getword(line, spos);
    if (cmd.empty() || match(cmd, "#"))
      continue;

    // Split remainder of line into words, which are the command arguments
    vector<string> args;
    while (spos != string::npos)
    {
      string w = getword(line, spos);
      if (!w.empty())
        args.push_back(w);
    }

    // Look up command in table and run the command routine
    for (j = 0; j < nCommands; j++)
      if (cmd.length() >= cmdTable[j].minlen && match(cmdTable[j].cmd, cmd))
      {
        cmdTable[j].cmdRtnP(&args);
        break;
      }
    if (j == nCommands)
    {
      Log("Invalid command.");
      helpCmd(NULL);
    }
    if (quitflag)
      break;
  }
  thLock(&workerMutex);
  thBcast(&workerCond);
  thUnlock(&workerMutex);

  shutReceivers();
  waitForThreads();

  for (b = 0; b < nRtBuckets; b++)
  {
    ReplyEntry *reP, *nextP;
    for (reP = pendReplyTab[b].freeListP; reP != NULL; reP = nextP)
    {
      nextP = reP->reNextP;
      delete reP;
    }
  }
  exit(EXIT_SUCCESS);
}
