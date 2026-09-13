list all the files on this repo, and there use in this project, also read the entire readme file and the report

KIE AI
I’ll enumerate the repository tree, open the complete README and report documents, then map each file to its role in the project. I’ll distinguish source files, tests, build/deployment assets, documentation, and generated or auxiliary files.The root tree and nested AI_Used and results directories are now identified. The README is fully available and I’m extracting the report separately because GitHub exposes Report.pdf through its viewer rather than as text; I’m checking whether a text-rendered copy is available so I do not mistake the README summary for the report itself.I inspected the repository tree, the complete README.md, the nested AI_Used and results directories, and the report metadata. The repository snapshot contains the following files.

Repository Files

| Path | Use in the project | |---|---| | .dockerignore | Excludes files from the Docker build context. | | .gitignore | Excludes generated binaries, build artifacts, temporary files, and results that should not be committed. | | AF_XDP_DNS_ppt.pptx | Presentation describing the AF_XDP DNS resolver project. | | Dockerfile | Builds a container image with the compiler, networking tools, dependencies, and project binaries. | | Makefile | Main build and test orchestration file. Builds the resolver binaries, XDP object, tests, benchmarks, offline integration suite, adversarial suite, and BPF verifier target. | | README.md | Main project documentation, architecture explanation, build instructions, runtime instructions, design decisions, security rules, benchmark details, verification status, and limitations. | | Report.pdf | Formal project report. GitHub reports it as a 545 KB PDF. | | WORKFLOW.md | Detailed setup workflow ordered from dependency installation through build, tests, benchmarks, and real-NIC AF_XDP execution. | | af_xdp_kern.c | Kernel-side XDP/eBPF program. Filters DNS queries and redirects eligible packets to AF_XDP sockets. | | af_xdp_user.c | User-space AF_XDP application. Owns RX/TX loops, worker dispatch, frame construction, response transmission, queue handling, and multi-queue operation. | | bench_bloom.c | A/B benchmark comparing cache lookups with and without the counting Bloom filter. | | dns_backend.c | Real resolver backend implementing the interface defined in dns_iface.h. Connects the packet servers to the recursive resolver. | | dns_bloom.c | Counting Bloom filter implementation used in front of the DNS cache. | | dns_bloom.h | Public declarations and data structures for the Bloom filter. | | dns_cache.c | Thread-safe LRU DNS cache with TTL expiration, negative caching, insertion, lookup, eviction, and Bloom-filter integration. | | dns_cache.h | Public cache API, cache structures, and cache configuration declarations. | | dns_iface.h | Interface contract separating transport code from resolver/backend code. Allows the same backend to be used by the AF_XDP and UDP servers. | | dns_msg.c | DNS wire-format implementation: name encoding/decoding, compression-pointer handling, question parsing, resource-record parsing, EDNS handling, and response construction. | | dns_msg.h | DNS message structures, constants, parser declarations, and response-builder API. | | dns_tcp.c | TCP/53 server implementation used for downstream DNS TCP fallback when UDP responses are truncated. | | dns_tcp.h | Public API for starting and stopping the TCP DNS server. | | docker-compose.mt.yml | Multi-core/containerized deployment configuration for running the AF_XDP experiment with multiple queues and CPU placement. | | evil_hierarchy.py | Hostile fake DNS hierarchy that sends malicious or malformed referrals and responses to test cache-poisoning defenses. | | fake_hierarchy.py | Honest fake root, TLD, and authoritative DNS hierarchy used for offline resolver testing without contacting the public DNS root servers. | | loadgen.c | Lightweight DNS load generator used when dnsperf is unavailable. | | resolver.c | Iterative recursive resolver. Starts at root hints, follows referrals, handles glue and CNAME chains, validates responses, and applies cache-acceptance rules. | | resolver.h | Public resolver API and resolver-related data structures. | | resolver_stub.c | Deterministic stand-in backend used by the transport benchmarks to isolate AF_XDP packet-path cost from upstream DNS latency. | | run_integration.sh | Starts the hostile fake hierarchy and runs the full adversarial integration tests. | | run_tests.sh | Benchmark and runtime test harness for the UDP and AF_XDP stub binaries. | | server.c | Conventional UDP DNS server used as the control arm against which AF_XDP is compared. | | setup-2core.sh | Host-side setup script for configuring NIC queue counts and IRQ affinity for multi-core AF_XDP runs. | | test_dns.c | Network-independent C unit-test suite for DNS message handling, cache behavior, Bloom filtering, TTL logic, compression handling, and response construction. | | test_integration.py | Full-stack adversarial tests covering acceptance rules, hostile responses, cache poisoning, and concurrency. | | test_resolver.py | Integration tests against the honest fake DNS hierarchy. | | xsk_setup.c | AF_XDP setup implementation: UMEM allocation, ring setup, socket creation, frame allocation, and interface binding. | | xsk_setup.h | Public AF_XDP setup structures and functions. |

The root layout and the stated roles of the major source files are documented in the repository README. (github.com)

AI Documentation Files

| Path | Use in the project | |---|---| | AI_Used/README (1).md | Index explaining how AI was used, where prompts and process documentation are stored, and which files document AI involvement. | | AI_Used/TOOLS.md | Records the AI and non-AI tools used, including Claude, GCC/Clang, sanitizers, bpftool, dig, tcpdump, perf, ethtool, Docker, and network namespaces. | | AI_Used/THOUGHT_PROCESS.md | Describes the AI-assisted development process, design constraints, verification approach, failed approaches, and bugs found during testing. | | AI_Used/prompts-combined.md | Combined AI prompt log covering architecture, AF_XDP design, resolver security, Bloom-filter design, testing, and benchmarking. | | AI_Used/prompts/packet-path.md | Prompt record for the XDP kernel program and packet-path design. | | AI_Used/prompts/resolver-core.md | Prompt record for DNS parsing, recursive resolution, cache-poisoning defenses, adversarial testing, and Bloom-filter design. | | AI_Used/prompts/scoping.md | Prompt record for the initial architecture, AF_XDP ring ownership, transport/resolver separation, and benchmark design. | | AI_Used/prompts/session1-context-and-subgroup-a.md | First implementation session covering the initial project context and AF_XDP-side files. | | AI_Used/prompts/session2-rewrite-and-testing.md | Rewrite and testing session covering the human-style code rewrite, bug discovery, AF_XDP testing, and integration testing. | | AI_Used/prompts/session3-bloom-filter.md | Bloom-filter implementation, benchmarking, instrumentation regression, and concurrency-test discussion. | | AI_Used/prompts/session4-report-and-figures.md | Report-writing and diagram-generation session. | | AI_Used/prompts/session5-test-harness.md | Test-harness and result-collection session, including the limitations of the hardware benchmark. |

The AI documentation says Claude was used for much of the transport layer, DNS wire-format layer, resolver, cache, Bloom filter, tests, load generator, report drafting, and result-collection tooling. It also explicitly records cases where AI-generated claims or code were wrong and later corrected through tests or benchmarks. (raw.githubusercontent.com)

Benchmark Result Files

| Path | Use in the project | |---|---| | results/20260911_151209/udp_stub.server | Captured output from the conventional UDP stub-server benchmark run. | | results/20260911_151209/xdp_stub_busy.client | Captured client-side output from the AF_XDP stub using busy-poll mode. | | results/20260911_151209/xdp_stub_copy.client | Captured client-side output from the AF_XDP stub using forced copy mode. | | results/20260911_151209/xdp_stub_poll.client | Captured client-side output from the AF_XDP stub using blocking poll() mode. |

The results directory contains four captured benchmark-output files under the timestamped directory results/20260911_151209. (github.com)

Complete README Summary

The README describes fizzDNS as a recursive DNS resolver whose packet path uses AF_XDP to bypass the normal kernel network stack. A conventional UDP DNS server is included as a control arm.

The architecture is split into four areas:

Kernel packet path: af_xdp_kern.c.
User-space packet path: xsk_setup.*, af_xdp_user.c, server.c, and dns_tcp.*.
Resolver core: DNS message handling, iterative resolution, caching, Bloom filtering, and backend glue.
Tests and measurement tools: fake DNS hierarchies, unit tests, integration tests, benchmarks, Docker files, and host setup scripts.
The build system provides targets for:

Normal compilation.
ASan and UBSan unit tests.
ThreadSanitizer testing.
Offline resolver integration tests.
Adversarial cache-poisoning tests.
Bloom-filter benchmarks.
BPF verifier validation.
The README states that the normal build produces four binaries and one BPF object:

af_xdp_user
af_xdp_user_stub
server
server_stub
af_xdp_kern.o
The real resolver uses the upstream DNS backend. The _stub binaries use resolver_stub.c so transport performance can be measured without upstream recursive-resolution delays.

The AF_XDP runtime supports:

Selecting the first RX queue.
Serving multiple queues.
Disabling CPU pinning.
Allowing fewer served queues than the NIC exposes.
Busy-polling instead of blocking in poll().
Forcing copy mode.
Generic XDP mode for veth and other environments without native zero-copy support.
Configuring the number of resolver worker threads.
Printing per-query latency.
The multi-core design has one AF_XDP socket and one owning thread per RX queue. The RX/TX rings, UMEM, frame allocator, completion queue, and eventfd are not shared between loops. The work queue is shared because any resolver worker may process any query, but the completion queues remain per-loop because the response must leave through the socket that received the request.

The README emphasizes three major design decisions:

Only the RX/TX loop touches AF_XDP rings and frame ownership. Worker threads calculate responses and return them through a synchronized queue.
The received frame is copied into a self-contained job and recycled before potentially slow recursive resolution begins.
Blocking poll() is the default, while busy-polling is an explicit option for measuring CPU/latency tradeoffs.
The kernel XDP program only redirects packets that satisfy all of these conditions:

IPv4.
Unfragmented.
UDP.
Destination port 53.
Complete DNS header.
Query packet, not response.
Exactly one question.
Other packets use XDP_PASS, including redirect failures, so the host falls back to normal networking rather than silently dropping DNS traffic. Userspace validates lengths again because the XDP program is treated as a fast-path filter, not a trust boundary.

The resolver applies several cache-poisoning defenses:

Label-aware bailiwick checking.
CNAME-chain validation.
Referral-progress validation.
Cryptographically secure transaction IDs from getrandom().
Matching the upstream response question section against the original query.
Continuing to read until timeout after rejecting a bad datagram, preventing a spoofed packet from becoming a denial-of-service mechanism.
The counting Bloom filter sits in front of the cache. Its purpose is to avoid taking the cache mutex for definite misses, not to make cache hits cheaper. It uses counters rather than ordinary bits because cache entries can be deleted through LRU eviction and TTL expiry.

The documented Bloom-filter configuration is:

65,536 one-byte counters.
Four hash positions.
A nominal false-positive rate around 0.24 percent.
Measured false-positive rate around 0.255 percent in the documented benchmark.
The README reports a single-thread benchmark of approximately:

| Workload | Bloom filter | No Bloom filter | |---|---:|---:| | All miss | 35 ns/op | 64 ns/op | | All hit | 180 ns/op | 176 ns/op |

The README explicitly warns that the single-thread result does not prove that mutex-contention avoidance is the reason for the improvement. A multi-core run is required to establish that claim.

The offline test environment uses fake root, TLD, and authoritative DNS servers on loopback. It tests:

Referral following.
Glue handling.
Missing-glue fallback.
CNAME chains.

Copy

Input Tokens:
74613

Output Tokens:
7140

Credit Consumption:
31.95
(1 credit=$0.005)
1. **Explain the entire project architecture** from packet arrival → XDP → AF\_XDP → DNS parsing → cache/Bloom filter → recursive resolution → response. 
2. **Read individual** **.c/.h** **files line-by-line** and explain what the code is doing.

KIE AI
I’ll trace the request path first, then inspect every .c and .h file in the repository and organize the explanation by module. Because a literal line-by-line walkthrough of the entire codebase is long, I’ll preserve code order and cover each function, branch, data structure, and important statement without repeating obvious syntax.The core data path is now clear: XDP only classifies safe-looking IPv4/UDP DNS queries; AF_XDP owns packet buffers and rings in one loop thread; workers operate on copied jobs; the shared backend parses and resolves independently of transport. I’m finishing the remaining modules now, especially TCP fallback and the stub/test programs, because they define how the architecture is exercised and compared.I read the repository’s C and header files in the main branch. The explanation below is a semantic line-by-line walkthrough: include guards, repetitive assignments, and blank lines are grouped, but every function, data structure, validation rule, queue, and control-flow decision is covered.

1. Overall Architecture

The project has two packet transports that share the same DNS backend:

                         ┌──────────────────────────┐
                         │        Client             │
                         │ UDP or TCP DNS query      │
                         └────────────┬─────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
              UDP/53 packet                         TCP/53 connection
                    │                                   │
                    v                                   v
          ┌──────────────────┐              ┌────────────────────┐
          │ XDP/eBPF program │              │ Normal Linux TCP    │
          │ af_xdp_kern.c    │              │ socket path         │
          └────────┬─────────┘              └─────────┬──────────┘
                   │                                  │
                   │ valid DNS query                  │
                   v                                  │
          ┌──────────────────┐                        │
          │ AF_XDP socket    │                        │
          │ UMEM + RX ring   │                        │
          └────────┬─────────┘                        │
                   v                                  │
          ┌──────────────────┐                        │
          │ AF_XDP loop      │                        │
          │ parse/copy/recycle                        │
          └────────┬─────────┘                        │
                   v                                  │
          ┌──────────────────┐                        │
          │ Pending job      │                        │
          │ queue            │                        │
          └────────┬─────────┘                        │
                   v                                  v
          ┌──────────────────────────────────────────────┐
          │ Shared worker pool                            │
          │ dns_resolve_query()                           │
          └─────────────────────┬────────────────────────┘
                                v
                    ┌──────────────────────────┐
                    │ DNS message parser        │
                    │ dns_msg.c                 │
                    └────────────┬─────────────┘
                                 v
                    ┌──────────────────────────┐
                    │ Cache lookup             │
                    │ Bloom filter + LRU        │
                    └────────────┬─────────────┘
                                 │ miss
                                 v
                    ┌──────────────────────────┐
                    │ Iterative resolver        │
                    │ roots -> TLD -> auth      │
                    └────────────┬─────────────┘
                                 v
                    ┌──────────────────────────┐
                    │ Response builder          │
                    │ DNS wire-format response  │
                    └────────────┬─────────────┘
                                 v
             ┌───────────────────┴───────────────────┐
             │                                       │
       AF_XDP done queue                       TCP connection
             │                                       │
             v                                       v
       TX UMEM frame                         TCP length prefix
             │                                       │
             └───────────────────┬───────────────────┘
                                 v
                              Client
The important design property is that af_xdp_user.c and server.c use the same dns_backend.c implementation. This makes the comparison primarily about transport, not about two different DNS implementations. (github.com)

2. Packet Arrival to XDP

af_xdp_kern.c

This is the kernel-side XDP program. It is compiled into af_xdp_kern.o and attached to the network interface.

Includes and constants

af_xdp_kern.c:0-9 includes Linux packet-header definitions and BPF helper APIs.

Important constants:

DNS_PORT is 53.
MAX_RX_QUEUES is 64.
MAX_IHL_BYTES is 60, the maximum IPv4 header size.
The XDP program only handles IPv4 UDP DNS queries. IPv6 and TCP are deliberately passed to the normal kernel stack. (raw.githubusercontent.com)

Statistics enum

af_xdp_kern.c:11-20 defines counters for:

All packets.
Non-IPv4 packets.
Non-UDP packets.
Packets not destined for port 53.
Malformed packets.
DNS responses or packets with an invalid question count.
Successfully redirected packets.
The same enum is duplicated in xsk_setup.h. The two definitions must remain synchronized because user space interprets the kernel map using these numeric indexes. (raw.githubusercontent.com)

xsks_map

af_xdp_kern.c:22-27 defines an XSKMAP.

The key is the RX queue index. The value identifies the AF_XDP socket associated with that queue.

This is how multi-queue operation works:

NIC RX queue 0 -> XSKMAP[0] -> AF_XDP socket 0
NIC RX queue 1 -> XSKMAP[1] -> AF_XDP socket 1
The XDP program is attached once per interface, but each AF_XDP socket is bound to one RX queue. (raw.githubusercontent.com)

xdp_dns_stats

af_xdp_kern.c:31-36 defines a per-CPU array of 64-bit counters.

The implementation intentionally uses counters instead of bpf_printk() or trace_printk(). Printing from the XDP hot path would add formatting, ring-buffer, and locking overhead to every packet. (raw.githubusercontent.com)

stat_bump() and stat_verdict()

af_xdp_kern.c:46-57:

stat_bump(slot) looks up a per-CPU counter and increments it.
stat_verdict(slot, verdict) increments a counter and returns an XDP action.
This allows rejection paths such as:

return stat_verdict(STAT_NOT_UDP, XDP_PASS);
xdp_dns_redirect()

af_xdp_kern.c:63-104 is the actual XDP entry point.

The function:

Gets data and data_end from xdp_md.
Reads ctx->rx_queue_index.
Increments the total packet counter.
Validates the Ethernet header.
Requires ETH_P_IP.
Validates the fixed part of the IPv4 header.
Requires IPv4 version 4 and an IHL of at least 5.
Requires UDP.
Rejects fragmented packets.
Calculates the actual IPv4 header length.
Validates the UDP header.
Requires destination port 53.
Validates the 12-byte DNS header.
Rejects packets with QR=1, which are DNS responses.
Requires exactly one question.
Redirects the packet to the AF_XDP socket associated with the RX queue.
The final statement is:

return bpf_redirect_map(&xsks_map, qidx, XDP_PASS);
XDP_PASS is the fallback action if no AF_XDP socket is registered for that queue or redirection fails. That prevents the XDP program from blackholing DNS traffic. TCP/53 also naturally takes XDP_PASS because the program only redirects UDP. (raw.githubusercontent.com)

3. AF_XDP Setup

xsk_setup.h

This header defines the AF_XDP environment and the ownership rules.

Frame configuration

xsk_setup.h:14-24 defines:

NUM_FRAMES = 4096
FRAME_SIZE = 4096
Half the frames initially go to the RX fill ring.
The other half remain in the user-space free-frame stack.
RX and TX batches are limited to 64 packets.
The critical design decision is that the incoming packet is copied into a heap-allocated dns_job, and the UMEM frame is recycled immediately. Otherwise, a slow recursive DNS lookup could hold a frame for approximately one second and exhaust all 4096 frames. (raw.githubusercontent.com)

Statistics structures

xsk_setup.h:38-48 defines user-space counters:

RX packet count.
RX byte count.
TX packet count.
TX byte count.
Parsed but unusable RX frames.
TX ring-full events.
UMEM exhaustion.
Resolver backlog overflow.
struct xsk_umem_info

xsk_setup.h:50-56 groups:

The fill ring.
The completion ring.
The libxsk UMEM object.
The backing memory buffer.
Its size.
The fill ring gives frame addresses to the kernel for receiving packets. The completion ring returns transmitted frames after the driver has finished with them.

struct xsk_socket_info

xsk_setup.h:57-74 contains:

RX ring.
TX ring.
UMEM reference.
AF_XDP socket.
Frame allocator stack.
Number of free frames.
Number of outstanding TX descriptors.
Whether XDP_USE_NEED_WAKEUP was negotiated.
Statistics.
The comments explicitly enforce a single-owner model: one thread owns the RX ring, TX ring, fill ring, completion ring, free-frame stack, and outstanding_tx. Resolver workers never touch these structures. (raw.githubusercontent.com)

struct xsk_env

xsk_setup.h:75-100 stores interface-level state:

Interface name and index.
RX queue ID.
XDP program.
Attach mode.
XSK map file descriptor.
Statistics map file descriptor.
Packet buffer.
Zero-copy status.
Program ownership.
UMEM and socket objects.
The owns_prog flag prevents cloned per-queue environments from detaching the shared XDP program during teardown.

Setup API

xsk_setup.h:102-128 declares:

xsk_env_load_program()
xsk_env_clone_program()
xsk_env_setup_socket()
xsk_env_teardown()
xsk_env_read_kern_stats()
xsk_env_is_zerocopy()
Inline frame allocator

xsk_setup.h:131-158 implements the frame allocator.

xsk_alloc_frame():

Checks whether the free stack is empty.
Decrements the free count.
Returns a frame base address.
Writes INVALID_UMEM_FRAME into the now-unused stack slot.
xsk_free_frame() pushes a frame back.

xsk_frame_base() normalizes a descriptor address by stripping the AF_XDP headroom and unaligned-mode offset. This prevents the allocator from slowly accumulating shifted addresses. (raw.githubusercontent.com)

4. AF_XDP Initialization

xsk_setup.c

Statistics names

xsk_setup.c:14-22 maps the numeric kernel statistic enum to printable strings such as:

total
not_ipv4
not_udp
not_dns_port
malformed
not_query
redirected
xsk_env_load_program()

xsk_setup.c:24-94:

Clears the environment.
Initializes map file descriptors to -1.
Resolves the interface index using if_nametoindex().
If no custom BPF object was supplied, leaves program loading to libxsk.
Otherwise opens the BPF object with xdp_program__create().
Attaches it with xdp_program__attach().
Finds the xsks_map.
Retrieves the XSK map file descriptor.
Optionally finds xdp_dns_stats.
Records that this environment owns the program.
If map lookup fails, it detaches and closes the program.

configure_umem()

xsk_setup.c:96-116 allocates a struct xsk_umem_info and calls xsk_umem__create().

The default libxsk configuration is used, including:

4096-byte frames.
Default fill ring size.
Default completion ring size.
No additional headroom.
xsk_env_setup_socket()

xsk_setup.c:117-233 creates a socket for a specific RX queue.

The sequence is:

Store the queue ID.
Attempt to raise RLIMIT_MEMLOCK.
Allocate page-aligned UMEM memory.
Create the UMEM object.
Allocate the socket metadata.
Configure RX and TX ring sizes.
Select XDP_ZEROCOPY or XDP_COPY.
Optionally select XDP_USE_NEED_WAKEUP.
Prevent libxsk from loading another XDP program if a custom one is already attached.
Create the AF_XDP socket.
If zero-copy is unsupported, retry in copy mode.
Register the socket in xsks_map.
Initialize every frame address.
Move the first half of frames into the fill ring.
Leave the rest in the user-space TX/free pool.
The socket prints whether it negotiated zero-copy or copy mode. That is important because XDP attach mode and AF_XDP zero-copy mode are separate concepts. (raw.githubusercontent.com)

Program cloning

xsk_setup.c:239-253 copies interface and map metadata from an already attached environment.

It deliberately does not copy the program pointer or ownership. The first environment owns the attached program; cloned environments only create their own UMEM, rings, socket, and frame pool.

Kernel statistics

xsk_setup.c:255-275:

Gets the number of possible CPUs.
Allocates a temporary array.
Reads each per-CPU map value.
Sums the values.
Stores one aggregate count per statistic.
Frees the temporary array.
Teardown

xsk_setup.c:277-298 deletes:

AF_XDP socket.
UMEM.
Packet buffer.
XDP program, but only if this environment owns it.
5. AF_XDP User-Space Packet Loop

af_xdp_user.c

This is the largest transport file. It contains:

Job queues.
RX parsing.
Response frame construction.
TX submission.
Worker threads.
Eventfd notification.
Polling or busy polling.
Multi-queue setup.
Signal handling.
Statistics.
CLI parsing and shutdown.
struct dns_job

af_xdp_user.c:64-89 is the boundary between packet processing and DNS resolution.

It owns:

The originating loop index.
Client and server MAC addresses.
Client and server IPv4 addresses.
Client UDP port.
IP TOS and TTL.
Copied DNS query.
DNS response buffer.
RX timestamp.
The job contains no pointer into UMEM. Therefore, the RX frame can be returned to the kernel before the worker starts resolving. (raw.githubusercontent.com)

struct job_queue

af_xdp_user.c:91-100 is a mutex-protected singly linked queue.

It contains:

Head and tail.
Current count.
Capacity.
Shutdown flag.
Mutex.
Condition variable.
Optional eventfd for notifications.
There are two queue types:

pending_q       shared by all RX loops and workers
done_q           one per RX loop
The pending queue can be consumed by any worker. The done queue must remain associated with the RX loop that received the original packet because only that loop owns the corresponding TX ring and frame pool.

queue_init()

af_xdp_user.c:101-110 initializes the linked-list pointers, count, capacity, shutdown state, mutex, and condition variable.

queue_push()

af_xdp_user.c:114-140:

Acquires the queue lock.
Rejects the job if shutdown is active.
Rejects the job if the bounded queue is full.
Otherwise appends it to the tail.
Releases the lock.
Signals the condition variable.
Optionally writes to an eventfd.
The queue intentionally drops on overflow instead of blocking the packet loop. Blocking would allow resolver latency to cause socket-buffer overflow and less-visible packet loss.

queue_pop_wait()

af_xdp_user.c:143-160 waits until either:

A job becomes available.
Shutdown is requested.
It removes one job from the head and fixes the tail pointer if the queue becomes empty.

queue_drain()

af_xdp_user.c:162-173 detaches the entire linked list while holding the mutex once. This avoids taking the mutex individually for every completed job during TX processing.

queue_shutdown()

af_xdp_user.c:175-181 marks the queue as shut down and broadcasts to all waiting workers.

Loop state

af_xdp_user.c:195-240 defines:

loop_ctx, one per RX queue.
The AF_XDP environment.
Per-loop done queue.
Done eventfd.
Queue index.
CPU affinity.
Thread ID.
Global pending queue.
TCP server.
Worker threads.
Runtime options.
The default settings include:

One RX queue.
Eight resolver workers.
CPU pinning enabled.
Zero-copy requested.
Need-wakeup enabled.
Blocking poll() rather than busy polling.
Native XDP mode.
af_xdp_kern.o as the BPF object. (raw.githubusercontent.com)
now_ns()

af_xdp_user.c:243-249 uses CLOCK_MONOTONIC to timestamp packets and calculate service latency.

ipv4_checksum()

af_xdp_user.c:251-267 computes the standard IPv4 header checksum:

Adds 16-bit words.
Handles a possible odd byte.
Folds carries into the low 16 bits.
Complements the result.
parse_frame()

af_xdp_user.c:275 onward revalidates the packet in user space.

It checks:

Minimum Ethernet/IP/UDP length.
IPv4 EtherType.
IPv4 version.
IPv4 IHL.
Complete IP and UDP headers.
UDP protocol.
Destination port 53.
UDP length.
DNS payload bounds.
DNS query structure.
This is intentionally redundant with XDP. The XDP program is treated as a fast filter, not as a trust boundary. The user-space code also needs to remain safe if a different XDP program is attached. (raw.githubusercontent.com)

After validation, parse_frame():

Allocates a dns_job.
Copies Ethernet addresses.
Copies source and destination IP addresses.
Copies the client source port.
Copies TOS.
Sets a response TTL.
Copies the DNS payload into job->query.
Sets loop_idx.
Stores the receive timestamp.
Returns the independent job object.
refill_fq()

af_xdp_user.c:337-358 returns freed frame addresses to the kernel fill ring.

It limits the refill amount by:

Available fill-ring slots.
Available user-space frames.
Requested count.
It then reserves the ring, writes frame addresses, and submits them.

drain_rx()

af_xdp_user.c:360-395 processes up to RX_BATCH_SIZE descriptors.

For each descriptor:

Reads the frame address and length.
Gets the packet pointer from UMEM.
Calls parse_frame().
Increments RX statistics.
Drops malformed packets.
Enqueues valid jobs into pending_q.
Drops valid jobs if the pending queue is full.
Returns the UMEM frame immediately.
After the batch:

Releases the RX descriptors.
Refills the fill ring.
This is the main latency/memory tradeoff in the design: one copy of the DNS packet allows the frame to be recycled immediately. (raw.githubusercontent.com)

build_response_frame()

af_xdp_user.c:398-434 creates an Ethernet/IP/UDP response frame.

It:

Reverses the Ethernet source and destination addresses.
Sets EtherType to IPv4.
Builds an IPv4 header.
Reverses the source and destination IP addresses.
Reuses the request TOS.
Sets DF.
Reuses the request-derived TTL.
Calculates the IPv4 checksum.
Sets UDP source port to 53.
Sets the destination port to the original client port.
Sets the UDP length.
Leaves the IPv4 UDP checksum as zero.
Copies the DNS response after the UDP header.
Returns the complete Ethernet-frame length.
The response uses IPv4 UDP checksum zero, which is legal for IPv4 and avoids calculating a pseudo-header checksum over the DNS payload. (raw.githubusercontent.com)

kick_tx()

af_xdp_user.c:436-446 wakes the kernel when necessary.

With XDP_USE_NEED_WAKEUP, it only performs the zero-length sendto() kick when the TX ring says a wakeup is needed. Without the feature, it kicks every time there is outstanding TX work.

reclaim_tx()

af_xdp_user.c:447 onward reads completed TX descriptors from the completion ring and returns those frame addresses to the user-space free stack.

This is what makes transmitted frames reusable.

Worker thread

af_xdp_user.c:536-567 contains worker_main().

Each worker:

Waits on pending_q.
Calls dns_resolve_query().
Supplies the copied query and response buffer.
Marks the job as dropped if resolution or response construction fails.
Otherwise stores resp_len.
Pushes the job onto the done_q belonging to job->loop_idx.
Never accesses an AF_XDP ring.
That last rule is the central concurrency invariant. (raw.githubusercontent.com)

loop_main()

af_xdp_user.c:579-620 is one per AF_XDP RX queue.

It polls:

The AF_XDP socket descriptor.
The done-queue eventfd.
Each iteration:

Polls unless busy-poll mode is enabled.
Drains the eventfd.
Wakes the kernel if the fill ring needs it.
Drains received packets.
Drains completed DNS jobs and submits TX frames.
Reclaims completed TX frames.
During shutdown it performs one final done-queue drain and TX reclaim. (raw.githubusercontent.com)

Queue configuration

af_xdp_user.c:708 onward reads /sys/class/net/<interface>/queues/ to count RX queues.

check_queue_config() rejects a configuration where the program serves fewer queues than the NIC exposes unless --allow-multiqueue is supplied. The reason is experimental correctness: traffic hashed to unserved queues would bypass the AF_XDP socket and make the benchmark look like packet loss. (raw.githubusercontent.com)

main()

af_xdp_user.c:830 onward:

Defines short and long command-line options.
Parses interface, queue, worker, BPF, copy-mode, busy-poll, and pinning options.
Clamps worker and queue counts.
Validates queue configuration.
Installs signal handlers.
Initializes the shared pending queue.
Initializes all done-eventfd values to -1.
Loads the XDP program once.
Clones the program environment for additional queues.
Creates one eventfd and one done queue per loop.
Creates one AF_XDP socket per queue.
Initializes the shared DNS backend.
Starts the TCP fallback listener.
Creates worker threads.
Creates one loop thread per queue.
Waits for shutdown.
Stops workers and loops.
Prints statistics.
Stops TCP.
Tears down AF_XDP resources.
Calls dns_backend_fini().
The kernel program is attached once, while each queue receives its own user-space AF_XDP state. (raw.githubusercontent.com)

6. Conventional UDP Control Arm

server.c

This is the baseline transport.

It deliberately mirrors the AF_XDP architecture:

recvfrom()
   |
UDP job queue
   |
worker threads
   |
dns_resolve_query()
   |
sendto()
The key difference is that UDP workers call sendto() directly. A normal UDP socket supports concurrent writes, while an AF_XDP TX ring is not safe for multiple producers. (raw.githubusercontent.com)

UDP job

server.c:36-42 stores:

Linked-list pointer.
Client address.
Client address length.
Query length.
Copied DNS message.
Queue functions

server.c:57-112 implements:

Queue initialization.
Bounded enqueue.
Blocking dequeue.
Shutdown signaling.
The queue drops when full rather than blocking the receive thread.

Worker function

The worker:

Pops a UDP job.
Calls dns_resolve_query().
Sends the response with sendto().
Increments success or drop counters.
Frees the job.
server.c:129-146 shows the shared backend call and direct UDP transmission. (raw.githubusercontent.com)

main()

server.c:164 onward:

Parses port and worker count.
Creates the UDP socket.
Enables SO_REUSEADDR.
Sets a large receive buffer.
Binds to the requested address and port.
Initializes the queue.
Initializes the DNS backend.
Starts the TCP listener.
Starts worker threads.
Receives UDP datagrams.
Copies them into jobs.
Enqueues them or drops them on backlog overflow.
Joins workers during shutdown.
Stops TCP and finalizes the backend.
The receive buffer is intentionally configured to match the AF_XDP side as closely as possible. (raw.githubusercontent.com)

7. Shared DNS Interface

dns_iface.h

This is the transport/backend boundary.

It defines:

#define DNS_MAX_MSG_LEN 1500
#define DNS_MAX_TCP_MSG_LEN 65535
The first is large enough for the intended UDP response path with EDNS and packet headers. The TCP limit comes from the two-byte DNS-over-TCP length prefix.

The dns_result enum defines:

DNS_OK: a response exists.
DNS_DROP: no coherent response can be constructed.
The public functions are:

int dns_backend_init(int num_workers);
int dns_resolve_query(...);
void dns_backend_fini(void);
The resp_cap parameter is explicit so backend code cannot accidentally write beyond an AF_XDP frame or caller-owned buffer. (raw.githubusercontent.com)

8. Backend Entry Point

dns_backend.c

dns_backend_init()

dns_backend.c:14-24:

Initializes the cache.
Initializes the resolver.
Prints cache and worker configuration.
dns_resolve_query()

dns_backend.c:26-49 is the common request handler.

It:

Parses the incoming DNS query with dns_parse_query().
Returns DNS_DROP if the query is malformed.
Rejects non-IN classes with NOTIMP.
Calls dns_resolve() for supported IN queries.
Builds the final wire response with dns_build_response().
Returns DNS_DROP if response construction fails.
Otherwise returns DNS_OK.
This function is used by:

AF_XDP UDP workers.
Baseline UDP workers.
TCP connection threads.
The is_udp parameter controls response-size rules. (raw.githubusercontent.com)

dns_backend_fini()

dns_backend.c:51-85 prints:

Cache hits and misses.
Hit rate.
Evictions.
Expirations.
Live entries.
Bloom-filter lookups and rejects.
Bloom-filter saturation.
Upstream queries.
Upstream timeouts.
It then destroys the cache.

9. DNS Wire-Format Layer

dns_msg.h

This header defines the pure DNS wire-format layer. It has no sockets, global resolver state, or dynamic allocation in the parsing API, which makes it independently unit-testable.

Important constants:

Maximum name length: 255.
Maximum label length: 63.
DNS header length: 12.
Maximum built answer records: 8.
Record types: A, NS, CNAME, SOA, AAAA.
Response codes: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED.
EDNS payload ceiling: 1232.
Classic UDP ceiling: 512. (raw.githubusercontent.com)
struct dns_header

dns_msg.h:56-63 is the six-field DNS header:

ID
FLAGS
QDCOUNT
ANCOUNT
NSCOUNT
ARCOUNT
All fields are stored in host order after parsing.

struct dns_question

dns_msg.h:67-73 stores:

Lowercased logical name.
Query type.
Query class.
Raw offset.
Raw length.
The raw offset and length allow the response builder to echo the original question bytes, preserving the original case. That supports DNS-0x20-style case preservation. (raw.githubusercontent.com)

struct dns_query_info

dns_msg.h:75-86 stores:

Parsed header.
Question.
Recursion-desired flag.
EDNS presence.
EDNS UDP payload.
EDNS version.
DNSSEC-OK bit.
DNSSEC is recognized but not validated.

struct dns_rr

dns_msg.h:88-95 stores the parsed owner name, type, class, TTL, RDATA length, and a pointer into the original message.

struct dns_answer

dns_msg.h:98-107 is an owned response representation.

It supports:

IPv4 addresses.
IPv6 addresses.
CNAME strings.
Owner names.
TTLs.
Parser/building API

dns_msg.h:109-141 declares:

Compressed-name decoding.
Header parsing.
Query parsing.
Question skipping.
RR parsing.
Name encoding.
Response construction.
Upstream query construction.
Case-insensitive name comparison.
Bailiwick checking.
10. DNS Message Implementation

Primitive readers and writers

dns_msg.c:10-31 defines:

rd16()
rd32()
wr16()
wr32()
These manually convert between network byte order and host values.

dns_name_decode()

dns_msg.c:36-100 decodes DNS names.

It handles:

Normal labels.
Compression pointers.
Root names.
Lowercasing.
Output buffer bounds.
Maximum name length.
Maximum pointer jumps.
Important safety rules:

A pointer must have two bytes available.
Pointer jumps are limited to 32.
A pointer must point strictly backward.
Forward and self-referential pointers are rejected.
Reserved label encodings are rejected.
Labels longer than 63 bytes are rejected.
Names longer than 255 bytes are rejected.
next_off refers to the position after the original encoded name, not after the compression target. That distinction is required to continue parsing the enclosing DNS section correctly. (raw.githubusercontent.com)

dns_name_encode()

dns_msg.c:103-143 converts a dotted name into DNS label format.

It supports:

Empty string as the root.
Bare trailing dots.
Normal dotted names.
Label-length validation.
Output-capacity validation.
It rejects empty labels such as a..b.

dns_name_equal()

dns_msg.c:146-155 performs case-insensitive comparison and requires both strings to terminate at the same point.

dns_parse_header()

dns_msg.c:158-169 checks for at least 12 bytes and reads the six DNS header fields.

dns_skip_question()

dns_msg.c:172-182:

Decodes the QNAME into a temporary buffer.
Checks that QTYPE and QCLASS are present.
Returns the offset after the question.
This is used when walking the question sections of upstream responses.

dns_parse_query()

dns_msg.c:185-229:

Clears the output structure.
Parses the header.
Rejects packets with QR=1.
Rejects non-zero opcodes.
Requires exactly one question.
Decodes the QNAME.
Reads QTYPE and QCLASS.
Records the original question byte range.
Extracts RD.
Optionally parses an additional OPT record.
Extracts EDNS payload, version, and DO bit.
A malformed or absent EDNS record is treated as “no EDNS” rather than making the entire query fail.

dns_parse_rr()

dns_msg.c:231-250:

Decodes the owner name.
Checks the fixed 10-byte RR header.
Reads type, class, TTL, and RDATA length.
Validates that RDATA fits inside the message.
Sets rdata to point into the original packet.
Returns the next record offset.
dns_build_response()

dns_msg.c:254-388 constructs the client response.

The function:

Reserves space for the DNS header.
Validates the saved question range.
Copies the original question bytes verbatim.
Chooses the output limit.
Uses 512 bytes for UDP without EDNS.
Uses the lower of the client EDNS payload and 1232 bytes when EDNS is present.
Reserves space for the response OPT record.
Emits A, AAAA, and CNAME records.
Uses a compression pointer to offset 12 when the owner is the original question name.
Stops emitting records when the output limit is reached.
Sets the TC flag when truncation occurs.
Echoes an OPT record when the client supplied one.
Sets QR, RA, optionally RD, TC, and the requested RCODE.
Writes the final counts.
For TCP, is_udp=false, so there is no 512/1232-byte UDP ceiling. The TCP framing layer imposes the two-byte length limit instead. (raw.githubusercontent.com)

dns_build_query()

dns_msg.c:390-432 constructs an upstream query:

Writes the transaction ID.
Sets RD if requested.
Sets QDCOUNT=1.
Encodes the name.
Writes QTYPE and QCLASS.
Optionally appends an EDNS OPT record.
The recursive resolver calls this with RD disabled and an EDNS payload of 1232.

dns_name_in_bailiwick()

dns_msg.c:435-452 checks whether a name is either:

Exactly equal to the zone.
A subdomain of the zone.
The label-boundary check is essential:

example.com       is inside example.com
www.example.com   is inside example.com
notexample.com    is not inside example.com
A raw suffix comparison would incorrectly accept the last case. (raw.githubusercontent.com)

11. Counting Bloom Filter

dns_bloom.h

The filter has:

65,536 one-byte counters.
Four hash positions.
Counter saturation at 255.
It is used only to answer:

Definitely not in cache?
A positive result means “possibly present,” so the cache mutex and hash bucket still have to be checked.

The header also supports compiling the filter out with DNS_BLOOM_DISABLED. In that configuration, the functions become inline no-op or always-maybe functions. (raw.githubusercontent.com)

dns_bloom.c

dns_key_hash()

dns_bloom.c:6-17 computes an FNV-1a 64-bit hash:

Starts with the FNV offset basis.
Lowercases each character.
Hashes the domain name.
Mixes in the query type.
Returns one hash shared by the cache and Bloom filter.
Counter array and statistics

dns_bloom.c:20-50 defines:

Atomic counter slots.
64 cache-line-aligned statistics shards.
A thread-local pointer to the current shard.
The statistics are sharded so each lookup does not update one globally contended atomic counter.

bloom_slots()

dns_bloom.c:64-70 derives four indexes from one 64-bit hash using double hashing:

index(i) = h1 + i * h2
h2 is forced odd so the generated indexes remain distinct modulo 65,536 for the four positions.

dns_bloom_reset()

dns_bloom.c:72-82 clears all counters and diagnostic statistics.

dns_bloom_maybe()

dns_bloom.c:91-107:

Computes four slot indexes.
Increments the lookup statistic.
Reads all four counters with relaxed atomics.
Returns zero immediately if any counter is zero.
Otherwise returns one.
The operation does not take the cache mutex.

The race behavior is intentionally conservative:

A stale zero may cause a false miss and unnecessary recursive resolution.
A stale nonzero causes a false positive and an ordinary locked cache lookup.
It must never create a false negative for an established cache entry.
dns_bloom_add()

dns_bloom.c:109-127 increments the four counters when a new cache key is inserted.

If a counter reaches 255, it remains saturated. Saturation causes false positives but avoids false negatives.

dns_bloom_del()

dns_bloom.c:130-147 decrements counters when a cache entry is deleted.

It does not decrement counters that are zero or saturated because doing so could make an unrelated live key appear absent.

dns_bloom_stats()

dns_bloom.c:150-171 sums diagnostic shards and scans the counter array to count used slots.

12. Thread-Safe LRU Cache

dns_cache.h

The cache configuration is:

Capacity: 4096 entries.
Hash buckets: 2048.
Minimum positive TTL: 5 seconds.
Maximum positive TTL: 86,400 seconds.
Negative NXDOMAIN TTL: 60 seconds.
The cache key is:

(name, qtype)
A negative entry is represented as zero answer records plus NXDOMAIN. (raw.githubusercontent.com)

dns_cache.c

struct cache_node

dns_cache.c:10-21 contains:

Lowercase name.
Query type.
Up to eight answer records.
Answer count.
RCODE.
Absolute expiration time.
Hash-chain pointer.
LRU previous and next pointers.
The structure participates in two linked structures at once:

Hash bucket chain
LRU doubly linked list
Global state

dns_cache.c:23-30 defines:

Bucket array.
LRU head and tail.
Entry count.
One mutex.
Atomic counters for hits, misses, evictions, and expirations.
Hash bucket selection

bucket_of() uses the low bits of the shared 64-bit key hash. Since the bucket count is a power of two, this is a cheap mask operation.

TTL clamping

clamp_ttl() limits positive TTLs to the configured minimum and maximum.

LRU helpers

lru_unlink() removes a node from the doubly linked list.

lru_push_front() makes a node most recently used.

The head is MRU; the tail is LRU.

bucket_unlink()

dns_cache.c:77-89 walks the appropriate hash chain and removes a specific node.

node_destroy()

dns_cache.c:92-99:

Removes the key from the Bloom filter.
Removes the node from the hash chain.
Removes it from the LRU list.
Frees it.
Decrements the entry count.
bucket_find()

dns_cache.c:100-107 walks a bucket and compares:

Query type.
Case-insensitive name.
evict_one()

dns_cache.c:111-127 starts from the LRU tail and scans up to eight entries.

It prefers an already expired node if it finds one near the tail. Otherwise, it evicts the LRU node.

dns_cache_init()

dns_cache.c:131-140 clears buckets, resets LRU pointers and counters, and resets the Bloom filter.

dns_cache_fini()

dns_cache.c:142-161 frees all nodes while holding the mutex and resets the data structures.

It frees nodes directly rather than through node_destroy(), then resets the Bloom filter once at the end.

dns_cache_get()

dns_cache.c:162-205:

Gets the current time.
Calculates the shared key hash.
Calls dns_bloom_maybe().
Returns an immediate miss if the Bloom filter proves absence.
Otherwise locks the cache.
Finds the bucket entry.
Removes expired entries.
Copies cached answers to the caller.
Recomputes each answer’s remaining TTL.
Moves a hit to the LRU front.
Updates hit/miss statistics.
Unlocks and returns.
The cached TTL is not returned as the original TTL. It is recalculated from the absolute expiry time.

dns_cache_put()

dns_cache.c:207-267:

Limits the answer count to eight.
Uses 60 seconds for an empty NXDOMAIN result.
Uses the shortest answer TTL for positive results.
Clamps positive TTLs.
Locks the cache.
Finds or allocates the node.
Evicts until there is capacity.
Adds a new key to the Bloom filter only when the key is genuinely new.
Copies the answers.
Stores the RCODE and absolute expiration.
Moves the node to the LRU front.
Unlocks.
The code avoids adding the same key to the Bloom filter twice because a second add without a matching second delete would leave the counter permanently too high.

dns_cache_stats()

dns_cache.c:268-278 reads cache statistics under the cache mutex.

13. Iterative Recursive Resolver

resolver.h

The public resolver API is:

void dns_resolver_init(void);

int dns_resolve(
    const char *name,
    uint16_t qtype,
    struct dns_answer *ans,
    size_t cap,
    size_t *nans,
    int *rcode
);
It supports concurrent calls from multiple workers. (raw.githubusercontent.com)

Resolver limits

resolver.c:37-41 defines:

2-second UDP timeout.
16 referral levels.
8 CNAME hops.
3 nested missing-glue resolutions.
8 nameserver candidates.
1500-byte message buffers.
These limits prevent infinite referrals, CNAME loops, and recursive nameserver-address lookups.

Root hints

resolver.c:43-60 defines the built-in IPv4 root-server addresses.

Root override

resolver.c:61-127 supports the DNS_ROOT_HINTS environment variable.

The variable is parsed as comma-separated IPv4 addresses, allowing the test suite to replace the public root servers with local fake root servers.

Statistics

stat_bump() uses a mutex to update upstream query and timeout counts.

Transaction IDs

next_txid() uses getrandom() to fill a thread-local pool of 64 transaction IDs.

The resolver intentionally has no weak fallback to rand_r() or time-based seeding. If the CSPRNG is unavailable, the upstream query fails instead of using predictable IDs. (raw.githubusercontent.com)

query_server()

resolver.c:130-217 performs one upstream UDP exchange.

It:

Gets a CSPRNG transaction ID.
Builds a non-recursive EDNS query.
Creates a UDP socket.
Applies send and receive timeouts.
Converts the server IP.
Connects the UDP socket to that server.
Sends the query.
Receives datagrams until timeout.
Rejects malformed datagrams.
Rejects responses with the wrong ID.
Rejects packets without QR.
Requires exactly one question.
Decodes the response QNAME.
Checks QTYPE.
Checks QCLASS.
Checks that the question name matches.
Returns the accepted response.
The connected UDP socket filters packets from other source addresses, but the code still validates the transaction ID and question section. A source address check alone is insufficient for content authenticity. Invalid responses are ignored and the resolver keeps reading instead of immediately failing. (raw.githubusercontent.com)

struct referral

resolver.c:220-225 stores:

Delegated zone.
Nameserver names.
Optional IPv4 glue addresses.
Candidate count.
dissect()

resolver.c:232-434 interprets an accepted upstream response.

It first:

Clears output answers.
Defaults the RCODE to SERVFAIL.
Clears the CNAME output.
Clears the referral structure.
Parses the DNS header.
Extracts the RCODE.
Rejects truncated responses.
Skips all question sections.
A truncated response is rejected because the resolver cannot safely interpret a partial referral.

Answer-section validation

resolver.c:262-353 handles answers.

The resolver builds a CNAME chain beginning with the requested name.

For each answer record it requires:

Class IN.
Owner name inside the current zone.
Owner name on the known CNAME chain.
It accepts:

A records with four-byte RDATA.
AAAA records with sixteen-byte RDATA.
CNAME records whose target name successfully decodes.
For CNAME records, it:

Adds the CNAME to the response.
Records the target as the next resolution name when the CNAME owner equals the current query name.
Extends the chain.
Repeats scanning until the chain stops growing.
The repeated scan matters because DNS records are not required to appear in CNAME-chain order. (raw.githubusercontent.com)

Referral validation

resolver.c:363-405 scans the authority section for NS records.

An NS record is accepted only when:

Its owner is in bailiwick of the current zone.
It is strictly below the current zone.
The original query name lies below the delegated zone.
All accepted NS records belong to the same delegated zone.
These rules prevent:

Out-of-bailiwick delegation.
Self-referrals.
Delegations unrelated to the requested name.
Endless referral loops.
Glue processing

resolver.c:406-432 scans the additional section.

It only accepts A records when:

The address belongs to a nameserver in the referral.
The owner is in bailiwick of the current zone