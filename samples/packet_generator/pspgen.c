#define _GNU_SOURCE

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <math.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <numa.h>
#include <pthread.h>

#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "psio.h"

/* headers for examining pcap packet */
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#define MAX_PATH	260
#define INET_ADDRSTRLEN		16
#define INET6_ADDRSTRLEN	46
#define ETH_EXTRA_BYTES	24  // preamble, padding bytes

/* custom flag definitions to examine pcap packet */
#define IPPROTO_IPv6_FRAG_CUSTOM 	44
#define IPPROTO_ICMPv6_CUSTOM		58
#define IPPROTO_OSPF_CUSTOM			89

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
	((((unsigned long)(n) & 0xFF00)) << 8) | \
	((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
	((((unsigned long)(n) & 0xFF00)) << 8) | \
	((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		  ((((unsigned long)(n) & 0xFF000000)) >> 24))


#define SEC_TICKS	2666702000

/* core-wise */
uint64_t accum_latency = 0;
uint64_t cnt_latency = 0;

int latency_measure = 0;
uint32_t magic_number;
int payload_offset;

int num_cpus;
int my_cpu;
int num_packets;
int ip_version;
int time_limit;
double offered_throughput = -1;

/* Available devices in the system */
static int num_devices = -1;
static struct ps_device devices[PS_MAX_DEVICES];

/* Used devices */
static int num_devices_registered = 0;
static int devices_registered[PS_MAX_DEVICES];

static bool debug = false;
static bool has_device_info = false;

/* Target neighbors */
static int num_neighbors = 0;
static uint8_t neighbor_ethaddrs[PS_MAX_DEVICES][ETH_ALEN];
static uint32_t neighbor_ipv4addrs[PS_MAX_DEVICES];
static uint8_t neighbor_ipv6addrs[PS_MAX_DEVICES][16];

/* Other options */
static bool randomize_flows = true; /** example: set false when testing all-matching IPsec tunnels */

struct ps_handle handles[PS_MAX_CPUS];

/* pcap_replaying: related variable & structs */
static bool mode_pkt_gen = false;
static bool mode_pcap_replaying = false;
static bool pcap_looping = false;
char pcap_filename[MAX_PATH] = {0, };
char *pcap_alloc_file;
size_t pcap_filesize;
long pcap_num_pkts_total;
long pcap_num_pkts_not_sent;		// pcap_replaying: temp
uint32_t pcap_file_linktype;

// from pcap format definition
typedef struct pcap_file_header {
	uint32_t magic;		/* magic number */
	u_short version_major;  /* major version number */
	u_short version_minor;	/* minor version number */
	int32_t  thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t linktype;	/* data link type */
} pcap_file_header_t;

typedef struct pcap_pkthdr {
	uint32_t ts_sec;	/* time stamp */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t caplen;	/* number of octets of packet saved in file */
	uint32_t len;		/* actual length of packet */
} pcap_pkthdr_t;

typedef struct pcap_pkt_info {
    size_t offset_pkt_content;  /* offset of captured packet in pcap file */
    int caplen;            /* actual captured length of packet */
    int len;               /* real length of packet on the link */
} pcap_pkt_info_t;
pcap_pkt_info_t *pcap_pkt_info_arr;
long	pkt_info_arr_index;
/* pcap_replaying: end */

static inline uint64_t ps_rdtsc()
{
    uint32_t xlo;
    uint32_t xhi;

    __asm__ __volatile__ ("rdtsc" : "=a" (xlo), "=d" (xhi));

    return xlo | (((uint64_t) xhi) << 32);
}

/* function to check whether hyperthreading is enabled or not
	copied from config.cc file in nShader */
static void _cpuid(int i, uint32_t regs[4])
{
//#ifdef _WIN32
//        __cpuid((int *)regs, (int)i);
//#else
        asm volatile
        ("cpuid" : "=a" (regs[0]), "=b" (regs[1]),
                   "=c" (regs[2]), "=d" (regs[3])
	         : "a" (i), "c" (0));
        // ECX is set to zero for CPUID function 4
//#endif
}

bool check_hyperthreading(void) {
	// Reference: http://stackoverflow.com/questions/2901694/
	uint32_t regs[4];
	// Get vendor string.
	char vendor[12];
	_cpuid(0, regs);
	((uint32_t *)vendor)[0] = regs[1]; // EBX
	((uint32_t *)vendor)[1] = regs[3]; // EDX
	((uint32_t *)vendor)[2] = regs[2]; // ECX

	// Get CPU features.
	_cpuid(1, regs);
	unsigned features = regs[3]; // EDX

	// Get logical core count per CPU.
	_cpuid(1, regs);
	unsigned logical = (regs[1] >> 16) & 0xff; // EBX[23:16]
	unsigned cores = logical;
	if (!strncmp(vendor, "GenuineIntel", 12)) {
		// Get DCP cache info
		_cpuid(4, regs);
		cores = ((regs[0] >> 26) & 0x3f) + 1; // EAX[31:26] + 1
	} else if (!strncmp(vendor, "AuthenticAMD", 12)) {
		// Get NC: Number of CPU cores - 1
		_cpuid(0x80000008, regs);
		cores = ((unsigned)(regs[2] & 0xff)) + 1; // ECX[7:0] + 1
	}

	// Detect hyper-threads.
   bool has_hyperthreads = (features & (1 << 28)) && (cores < logical);
   return has_hyperthreads;
}
///

int ps_get_num_cpus() {
	// Assuming there is 2 hyper thread per physical CPU core..
	long num_physical_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	int hyper = check_hyperthreading();
	if (hyper) {
		num_physical_cpu /= 2;	
	}
	
	//printf("# of cpus: %d, hyperthreading: %d\n", num_physical_cpu, hyper);
	return num_physical_cpu;
}

int ps_bind_cpu(int cpu) {
	cpu_set_t *cmask;
	struct bitmask *bmask;
	size_t ncpu, setsize;
	int ret;

	ncpu = ps_get_num_cpus();

	if (cpu < 0 || cpu >= (int) ncpu) {
		errno = -EINVAL;
		return -1;
	}

	cmask = CPU_ALLOC(ncpu);
	if (cmask == NULL)
		return -1;

	setsize = CPU_ALLOC_SIZE(ncpu);
	CPU_ZERO_S(setsize, cmask);
	CPU_SET_S(cpu, setsize, cmask);

	ret = sched_setaffinity(0, setsize, cmask);

	CPU_FREE(cmask);

	/* skip NUMA stuff for UMA systems */
	if (numa_available() == -1 || numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(PS_MAX_CPUS);
	assert(bmask);

	numa_bitmask_setbit(bmask, cpu % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}

bool ps_in_samenode(int cpu, int ifindex)
{
	if (numa_available() == -1 || numa_max_node() == 0)
		return true;

	assert(ifindex >= 0);
	assert(ifindex < PS_MAX_DEVICES);

	/* CPU 0,2,4,6,... -> Node 0,
	 * CPU 1,3,5,7,... -> Node 1. */
	int cpu_node = numa_node_of_cpu(cpu);
	assert(cpu_node != -1);

	if (!has_device_info) {
		assert(ps_list_devices(devices) > 0);
		has_device_info = true;
	}
	int if_node = devices[ifindex].numa_node;
	assert(if_node < numa_num_configured_nodes());

	return cpu_node == if_node;
}

/// pcap_replaying	
void preprocess_pcap_file() {
	FILE *file;
	size_t read_size;
	size_t offset = 0;
	pcap_pkthdr_t *captured_pkt_hdr;
	pcap_pkt_info_t *pkt_info;

	pcap_num_pkts_total = 0;
	long index = 0;
	
	printf("Now preprocessing pcap file..\n");

	file = fopen(pcap_filename, "r");
	if (file == NULL) {
		fprintf(stderr, "Cannot open the pcap file \"%s\".\n", pcap_filename);
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	pcap_filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	pcap_alloc_file = (char*)malloc(pcap_filesize);
	read_size = fread(pcap_alloc_file, pcap_filesize, 1, file);

	if (read_size == -1) {
		fprintf(stderr, "Failed to read pcap file \"%s\".\n", pcap_filename);
		exit(1);
	}

    pcap_file_header_t *pcap_file_hdr;
    pcap_file_hdr = (pcap_file_header_t *)pcap_alloc_file;
    printf("Link type of packet trace: %u\n", pcap_file_hdr->linktype);
    pcap_file_linktype = pcap_file_hdr->linktype;

	// 1. look through pcap file & count whole number of packets
	offset += sizeof(pcap_file_header_t);
	while (offset < pcap_filesize) {
		captured_pkt_hdr = (pcap_pkthdr_t*) (pcap_alloc_file + offset);
		//printf("Packet #%d captured length: %d\n", pcap_num_pkts_total+1, captured_pkt_hdr->caplen);
		offset += sizeof(pcap_pkthdr_t);
		offset += captured_pkt_hdr->caplen;
		pcap_num_pkts_total++;	
	}

	// 2. alloc packet info array
	pcap_pkt_info_arr = (pcap_pkt_info_t*) malloc(pcap_num_pkts_total * sizeof(pcap_pkt_info_t));

	// 3. set packet info into array
	offset = sizeof(pcap_file_header_t);
	while (offset < pcap_filesize) {
		captured_pkt_hdr = (pcap_pkthdr_t*) (pcap_alloc_file + offset);
		//printf("Packet #%d captured length: %d\n", pcap_num_pkts_total+1, captured_pkt_hdr->caplen);
		offset += sizeof(pcap_pkthdr_t);
		pkt_info = &pcap_pkt_info_arr[index];
		pkt_info->offset_pkt_content = offset;
		pkt_info->caplen = captured_pkt_hdr->caplen;
		pkt_info->len	= captured_pkt_hdr->len;
		offset += captured_pkt_hdr->caplen;
		index++;	
	}

	printf("File size: %zu, number of packet: %ld\n", pcap_filesize, pcap_num_pkts_total);
}

void done()
{
	struct ps_handle *handle = &handles[my_cpu];

	uint64_t total_tx_packets = 0;

	int i;
	int ifindex;

	usleep(10000 * (my_cpu + 1));

	for (i = 0; i < num_devices_registered; i++) {
		ifindex = devices_registered[i];
		total_tx_packets += handle->tx_packets[ifindex];
	}

//	if (mode_pcap_replaying) {
//		printf("CPU#%d: current pkt info index: %ld\n", my_cpu, pkt_info_arr_index);
//	}
	printf("----------\n");
	printf("CPU %d: total %ld packets transmitted\n", 
			my_cpu, total_tx_packets);
	if (mode_pcap_replaying) {
		printf("CPU %d: total %ld packets not transmitted due to TX drop\n", my_cpu, pcap_num_pkts_not_sent);	// pcap_replaying 
	}

	for (i = 0; i < num_devices_registered; i++) {
		char *dev = devices[devices_registered[i]].name;
		ifindex = devices_registered[i];

		if (handle->tx_packets[ifindex] == 0)
			continue;

		printf("  %s: %ld packets "
				"(%ld chunks, %.2f packets per chunk)\n", 
				dev, 
				handle->tx_packets[ifindex],
				handle->tx_chunks[ifindex],
				handle->tx_packets[ifindex] / 
				  (double)handle->tx_chunks[ifindex]);
	}

	exit(0);
}

#define MAX_CONNS (PS_MAX_DEVICES * 64)
static uint64_t _rate[MAX_CONNS];
static uint64_t _started_at[MAX_CONNS];
static uint64_t _sent[MAX_CONNS];
static uint64_t get_usec(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return now.tv_sec * 1000000l + now.tv_usec;
}
static void init_rate_limit(int conn_id, uint64_t rate)
{
	_rate[conn_id] = rate;
	_started_at[conn_id] = get_usec();
	_sent[conn_id] = 0;
}
static unsigned check_rate(int conn_id)
{
	uint64_t now = get_usec();
	unsigned should_have_sent = (unsigned)((now - _started_at[conn_id]) / 1.0e6 * _rate[conn_id]);
	//printf("sent %lu, should_have_sent %lu, diff %lu\n", _sent[conn_id], should_have_sent, should_have_sent - _sent[conn_id]);
	return should_have_sent - _sent[conn_id];
}
static void update_rate(int conn_id, uint64_t value)
{
	_sent[conn_id] += value;
}

void handle_signal(int signal)
{
	done();
}

void update_stats(struct ps_handle *handle)
{
	static int total_sec = 0;
	static long counter;
	static time_t last_sec = 0;
	static int first = 1;

	static long last_total_tx_packets = 0;
	static long last_total_tx_bytes= 0;
	static long last_device_tx_packets[PS_MAX_DEVICES];
	static long last_device_tx_bytes[PS_MAX_DEVICES];

	long total_tx_packets = 0;
	long total_tx_bytes = 0;

	struct timeval tv;
	int sec_diff;

	int i;

	if (++counter % 100 != 0) 
		return;

	assert(gettimeofday(&tv, NULL) == 0);

	if (tv.tv_sec <= last_sec)
		return;

	sec_diff = tv.tv_sec - last_sec;

	for (i = 0; i < num_devices_registered; i++) {
		int ifindex = devices_registered[i];
		total_tx_packets += handle->tx_packets[ifindex];
		total_tx_bytes += handle->tx_bytes[ifindex];
	}

	if (!first) {
		long pps = total_tx_packets - last_total_tx_packets;
		long bps = (total_tx_bytes - last_total_tx_bytes) * 8;

		pps /= sec_diff;
		bps /= sec_diff;

		printf("CPU %d: %8ld pps, %6.3f Gbps "
				"(%.2f packets per chunk)",
				my_cpu, 
				pps,
				(bps + (pps * 24) * 8) / 1000000000.0,
				total_tx_packets / (double)counter);

		if (latency_measure && cnt_latency > 0) {
			printf(" %9.2f us %7lu", ((accum_latency / cnt_latency) / (SEC_TICKS / 1000000.0)), cnt_latency);
			accum_latency = 0;
			cnt_latency = 0;
		}

		for (i = 0; i < num_devices_registered; i++) {
			char *dev;
			int ifindex;

			dev = devices[devices_registered[i]].name;
			ifindex = devices_registered[i];

			if (!ps_in_samenode(my_cpu, ifindex))
				continue;

			pps = handle->tx_packets[ifindex] -
					last_device_tx_packets[ifindex];
			bps = (handle->tx_bytes[ifindex] -
					last_device_tx_bytes[ifindex]) * 8;

			printf("  %s:%8ld pps,%6.3f Gbps", 
					dev,
					pps,
					(bps + (pps * 24) * 8) / 1000000000.0);
		}

		printf("\n");
		fflush(stdout);

		total_sec++;
		if (total_sec == time_limit)
			done();
	}

	if (sec_diff == 1)
		first = 0;

	last_sec = tv.tv_sec;
	last_total_tx_packets = total_tx_packets;
	last_total_tx_bytes = total_tx_bytes;

	for (i = 0; i < PS_MAX_DEVICES; i++) {
		last_device_tx_packets[i] = handle->tx_packets[i];
		last_device_tx_bytes[i] = handle->tx_bytes[i];
	}
}

static inline uint32_t myrand(uint64_t *seed) 
{
	*seed = *seed * 1103515245 + 12345;
	return (uint32_t)(*seed >> 32);
}

#define RECV_CHUNK_SIZE	512
void receive_packets(struct ps_handle *handle, struct ps_chunk *chunk, int blocking)
{
	chunk->cnt = RECV_CHUNK_SIZE;
	chunk->recv_blocking = blocking;

	while (1) {
		int ret = ps_recv_chunk(handle, chunk);
		
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			if (!chunk->recv_blocking && errno == EWOULDBLOCK)
				break;

			assert(0);
		}

		if (ret > 0) {
			char *ptr = chunk->buf + chunk->info[ret - 1].offset + payload_offset;
			if (*(uint32_t *)ptr == magic_number) {
				uint64_t old_rdtsc = *(uint64_t *)(ptr + 4);
				cnt_latency++;
				accum_latency += ps_rdtsc() - old_rdtsc;
			}
		}

		chunk->cnt = RECV_CHUNK_SIZE;
		chunk->recv_blocking = 0;
	}
}

void build_packet(char *buf, int size, uint64_t *seed)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;

	uint32_t rand_val;

	/* Build an ethernet header */
	eth = (struct ethhdr *)buf;
	eth->h_proto = HTONS(ETH_P_IP);
	
	/* Note: eth->h_source and eth->h_dest are written at send_packets(). */

	/* Build an IPv4 header. */
	ip = (struct iphdr *)(buf + sizeof(*eth));

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = HTONS(size - sizeof(*eth));
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 4;
	ip->protocol = IPPROTO_UDP;
	/* Currently we do not test source-routing. */
	ip->saddr = HTONL(0x0A000001);
	if (randomize_flows) {
		/* Prevent generation of multicast packets, though its probability is very low. */
		ip->daddr = HTONL(myrand(seed));
		unsigned char *daddr = (unsigned char*)(&ip->daddr);
		daddr[0] = 0x0A;
	} else {
		uint64_t s = ++(*seed);
		ip->daddr = HTONL(0x0A000000 | (s & 0x00FFFFFF));
	}

	ip->check = 0;
	ip->check = ip_fast_csum(ip, ip->ihl);

	udp = (struct udphdr *)((char *)ip + sizeof(*ip));

	if (randomize_flows) {
		rand_val = myrand(seed);
		udp->source = HTONS(rand_val & 0xFFFF);
	} else
		rand_val = 80;
	/* For debugging, we fix the source port. */
	udp->source = HTONS(9999);
	udp->dest = HTONS((rand_val >> 16) & 0xFFFF);

	udp->len = HTONS(size - sizeof(*eth) - sizeof(*ip));
	udp->check = 0;

	/* For debugging, we fill the packet content with a magic number 0xf0. */
	char *content = (char *)((char *)udp + sizeof(*udp));
	memset(content, 0xf0, size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
	memset(content, 0xee, 1);  /* To indicate the beginning of packet content area. */
}

void build_packet_v6(char *buf, int size, uint64_t *seed)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip;
	struct udphdr *udp;

	uint32_t rand_val;

	/* Build an ethernet header. */
	eth = (struct ethhdr *)buf;
	eth->h_proto = HTONS(ETH_P_IPV6);

	/* Note: eth->h_source and eth->h_dest are written at send_packets(). */

	/* Build an IPv6 header. */
	ip = (struct ipv6hdr *)(buf + sizeof(*eth));

	ip->version = 6;
	ip->payload_len = HTONS(size - sizeof(*eth) - sizeof(*ip));
	ip->hop_limit = 4;
	ip->nexthdr = IPPROTO_UDP;
	/* Currently we do not test source-routing. */
	ip->saddr.s6_addr32[0] = HTONL(0x0A000001);
	ip->saddr.s6_addr32[1] = HTONL(0x00000000);
	ip->saddr.s6_addr32[2] = HTONL(0x00000000);
	ip->saddr.s6_addr32[3] = HTONL(0x00000000);
	ip->daddr.s6_addr32[0] = HTONL(myrand(seed));
	ip->daddr.s6_addr32[1] = HTONL(myrand(seed));
	ip->daddr.s6_addr32[2] = HTONL(myrand(seed));
	ip->daddr.s6_addr32[3] = HTONL(myrand(seed));

	// TODO: implement randomize_flows flag for IPv6 too.

	/* Prevent generation of multicast packets. */
	unsigned char *daddr = (unsigned char*)(&ip->daddr.s6_addr32[0]);
	daddr[0] = 0x0A;

	udp = (struct udphdr *)((char *)ip + sizeof(*ip));

	rand_val = myrand(seed);
	udp->source = HTONS(rand_val & 0xFFFF);
	udp->dest = HTONS((rand_val >> 16) & 0xFFFF);

	udp->len = HTONS(size - sizeof(*eth) - sizeof(*ip));
	udp->check = 0;

	/* For debugging, we fill the packet content with a magic number 0xf0. */
	char *content = (char *)((char *)udp + sizeof(*udp));
	memset(content, 0xf0, size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
	memset(content, 0xee, 1);  /* To indicate the beginning of packet content area. */
}

/// pcap_replaying
void build_packet_from_pcap(char *buf, char* packet, int captured_size, int actual_size) {
    // Copy the whole captured pcap packet.
    // It's okay because currently we only use ethernet address in routing, which is overwritten after packet is built.
    size_t filled_size = 0;

    if (pcap_file_linktype == 1) /* LINKTYPE_ETHERNET */ 
    {
        memcpy(buf, packet, captured_size);
        filled_size = captured_size;
    }
    else if (pcap_file_linktype == 101) /* LINKTYPE_RAW */
    {
        // Just to check whether raw packet is IPv4 or IPv6.
        // It is okay because the version field of IPv4 & IPv6 is in same position.
        // XXX: This code only handles IPv4 & IPv6 packet as L3 packet.
        struct iphdr *l3_header = (struct iphdr *)packet;
        struct ethhdr *eth = (struct ethhdr *) buf;

        if (l3_header->version == 4) {
            eth->h_proto = HTONS(ETH_P_IP);
        }
        else if (l3_header->version == 6) {
            eth->h_proto = HTONS(ETH_P_IPV6);
        }
        memcpy(buf + sizeof(*eth), packet, captured_size);
        filled_size = sizeof(*eth) + captured_size;
    }
    else {
        printf("Linktype %d of pcap file is unhandled currently.\n", pcap_file_linktype);
        exit(1); 
    }

    if (filled_size < actual_size) {
        // Fill the rest of packet with a magic number 0xf0.
        memset(buf + filled_size, 0xf0, actual_size - filled_size);
        memset(buf + filled_size, 0xee, 1); // Indicating the beginning of packet content area.
    }
}
///

#define MAX_FLOWS 16384

void send_packets(long packets, 
		int chunk_size,
		int packet_size,
		int min_packet_size,
		int num_flows,
		int loop_count)
{
	struct ps_handle *handle = &handles[my_cpu];
	struct ps_chunk chunk;
	static char packet[MAX_FLOWS][PS_MAX_PACKET_SIZE];
	int ret;

	int i, j;
	unsigned int next_flow[PS_MAX_DEVICES];
	char strbuf[128];

	long sent = 0;
	uint64_t seed = 0;

	if (num_flows == 0)
		seed = time(NULL) + my_cpu;

	/// pcap_replaying
	pkt_info_arr_index = my_cpu;
	pcap_num_pkts_not_sent = 0;
	///
	
	// NOTE: If the num_flows option is used, the flow is generated
	// with maximum sized packets and those sizes are cut randomly when
	// filling the output chunk.
	for (i = 0; i < num_flows; i++) {
		if (ip_version == 4) 
			build_packet(packet[i], packet_size, &seed);
		else if (ip_version == 6)
			build_packet_v6(packet[i], packet_size, &seed);
	}

	assert(ps_init_handle(handle) == 0);

	for (i = 0; i < num_devices_registered; i++) {
		next_flow[i] = 0;

		if (latency_measure) {
			struct ps_queue queue;
			if (!ps_in_samenode(my_cpu, devices_registered[i]))
				continue;

			queue.ifindex = devices_registered[i];
			queue.qidx = my_cpu / numa_num_configured_nodes();
			printf("attaching RX queue xge%d:%d to CPU%d\n", queue.ifindex, queue.qidx, my_cpu);
			assert(ps_attach_rx_device(handle, &queue) == 0);

			if (ip_version == 4)
				payload_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
			else
				payload_offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr) + 4;
		}
	}

	assert(ps_alloc_chunk(handle, &chunk) == 0);
	chunk.queue.qidx = my_cpu; /* CPU_i holds ring_i */

	assert(chunk.info);

	// The unit of actual rate is bytes/sec.
	if (offered_throughput > 0) {
		int num_used_devices = 0;
		for (i = 0; i < num_devices_registered; i++)
			if (ps_in_samenode(my_cpu, devices_registered[i]))
				num_used_devices ++;
		// Calculate rates for me.
		// The net rate of all pspgen instances should be offered_throughput.
		uint64_t actual_rate = (offered_throughput * 1.0e9 / 8) /
					(num_cpus * num_used_devices);
		for (i = 0; i < num_devices_registered; i++)
			init_rate_limit(i, actual_rate);
	}

	while (1) {
		int working = 0;

		for (i = 0; i < num_devices_registered; i++) {
			if (!ps_in_samenode(my_cpu, devices_registered[i]))
				continue;
			chunk.queue.ifindex = devices_registered[i];
			chunk.queue.qidx = my_cpu;

			working = 1;

			if (packets - sent < chunk_size)
				chunk.cnt = packets - sent;
			else
				chunk.cnt = chunk_size;

			/// pcap_replaying: TODO: handle throughput regulation for pcap replaying
			if (offered_throughput > 0) {
				unsigned need_to_send_bytes = check_rate(i);
				if (need_to_send_bytes < 0) {
					usleep(-need_to_send_bytes / _rate[i] * 1000000);
					continue;
				}
				chunk.cnt = ((chunk.cnt * (ETH_EXTRA_BYTES + packet_size)) > need_to_send_bytes) ?
					    (need_to_send_bytes / (ETH_EXTRA_BYTES + packet_size)) :
					    chunk.cnt;
				if (chunk.cnt == 0) {
					pthread_yield();
					continue;
				}
				update_rate(i, chunk.cnt * (ETH_EXTRA_BYTES + packet_size));
			}

			/* Fill the chunk with packets generated. */
			size_t offset = 0;	
			for (j = 0; j < chunk.cnt; j++) {
				int cur_pkt_size;

				/// pcap_replaying
				if (mode_pcap_replaying) {
					// cur_pkt_size is determined from pcap file
					pcap_pkt_info_t *packet;
					packet = &pcap_pkt_info_arr[pkt_info_arr_index];
					cur_pkt_size = packet->len;
					chunk.info[j].offset = offset;
					chunk.info[j].len = cur_pkt_size;
				
					build_packet_from_pcap(chunk.buf + chunk.info[j].offset, pcap_alloc_file + packet->offset_pkt_content, packet->caplen, packet->len);
					
                    if (pkt_info_arr_index < (pcap_num_pkts_total-1-num_cpus)) {
						pkt_info_arr_index += num_cpus;
					}
					offset = PS_ALIGN(offset + cur_pkt_size, 64);
					//printf("pcap_replaying: captured length:%d, pkt length:%d, offset:%d\n", header.caplen, header.len, offset);
				}
				///
				else { 
					if (min_packet_size < packet_size)
						cur_pkt_size = random() % (packet_size - min_packet_size) + min_packet_size;
					else
						cur_pkt_size = packet_size;
					chunk.info[j].len = cur_pkt_size;
					chunk.info[j].offset = offset;
					offset = PS_ALIGN(offset + cur_pkt_size, 64);

					if (num_flows == 0) {
						if (ip_version == 4) {
							build_packet(chunk.buf + chunk.info[j].offset,
									 cur_pkt_size, &seed);
						} else {
							build_packet_v6(chunk.buf + chunk.info[j].offset,
								cur_pkt_size, &seed);
						}
					} else {
						memcpy_aligned(chunk.buf + chunk.info[j].offset, 
							packet[(next_flow[i] + j) % num_flows], 
							cur_pkt_size);
					}
				}

				/* Write the src/dest ethernet address corresponding to the
				 * outgoing ifindex, like 1-to-1 wired setup. */
				struct ethhdr *eth = (struct ethhdr *)(chunk.buf + chunk.info[j].offset);
				//if (num_neighbors == num_devices) {
					memcpy(eth->h_dest, neighbor_ethaddrs[chunk.queue.ifindex], ETH_ALEN);
				//} else if (num_neighbors == num_devices * 2) {
				//	/* Alternate dest MAC addrs. */
				//	memcpy(eth->h_dest, neighbor_ethaddrs[(chunk.queue.ifindex * 2) + (j % 2)], ETH_ALEN);
				//} else {
				//	printf("num_neighbors %d, dev %d, dev reg %d\n", num_neighbors, num_devices, num_devices_registered);
				//	assert(0);
				//}
				memcpy(eth->h_source, devices[chunk.queue.ifindex].dev_addr, ETH_ALEN);
				if (debug) {
					printf("len %d %d eth_hlen %ld ", cur_pkt_size, chunk.info[j].len, sizeof(struct ethhdr));
					ether_ntoa_r((struct ether_addr *) eth->h_source, strbuf);
					printf("src %s ", strbuf);
					ether_ntoa_r((struct ether_addr *) eth->h_dest, strbuf);
					printf("dst %s\n", strbuf);
				}
			}

			if (latency_measure) {
				for (j = 0; j < chunk.cnt; j++) {
					char *ptr = chunk.buf + (chunk.info[j].offset + payload_offset);
					*((uint32_t *)ptr) = magic_number;
					*((uint64_t *)(ptr + 4)) = ps_rdtsc();
				}
			}

			ret = ps_send_chunk(handle, &chunk);
			if (ret < 0) {
				perror("ps_send_chunk");
				printf("arr_index: %ld\n", pkt_info_arr_index);// pcap_replaying
			}
			assert(ret >= 0);

			/// pcap_replaying: checking the number of packets not sent
			pcap_num_pkts_not_sent += chunk.cnt - ret;
			// TODO: re-try to send remaining packets	
			///

			update_stats(handle);
			sent += ret;

			if (latency_measure) {
				for (j = 0; j < loop_count; j++)
					receive_packets(handle, &chunk, packets <= sent);
			}

			if ( (mode_pcap_replaying) && (pkt_info_arr_index >= (pcap_num_pkts_total-1-num_cpus))) {
				if (pcap_looping) {
					sent = 0;
					pkt_info_arr_index = my_cpu;
				}
				else {
					printf("CPU#%d: End of pcap file\n", my_cpu);
					done();
				}
			}

			if (packets <= sent)
				done();

			if (num_flows)
				next_flow[i] = (next_flow[i] + ret) % num_flows;
		}

		if (!working)
			break;
	}

	ps_close_handle(handle);
}

void print_usage(char *program)
{
	fprintf(stderr, "usage: %s "
			"[-n <num_packets>] "
			"[-s <chunk_size>] "
			"[-p <packet_size>] "
			"[--min-pkt-size <min_packet_size>] "
			"[-f <num_flows>] "
			"[-r <randomize flows>] "
			"[-v <ip version>] "
			"[-l <latency measure>] "
			"[-c <loop count>] "
			"[-t <seconds>] "
			"[-g <offered throughput>] "
			"[--debug] "
			"[--neighbor-conf <neighbor config file>] "
			"-i all|dev1 [-i dev2] ...\n",
			program);

	/// pcap_replaying
	fprintf(stderr, "Or, to replay pcap file: -i all|dev1 [-i dev2] ... --pcap <pcap_file_name> [--loop]\n");
	///

	fprintf(stderr, "  default <num_packets> is 0. (0 = infinite)\n");
	fprintf(stderr, "    (note: <num_packets> is a per-cpu value.)\n");
	fprintf(stderr, "  default <chunk_size> is 64. packets per chunk\n");
	fprintf(stderr, "  default <packet_size> is 60. (w/o 4-byte CRC)\n");
	fprintf(stderr, "  default <min_packet_size> is same to <packet_size>.\n"
			"    If set, it will generate packets randomly sized\n"
			"    between <min_packet_size> and <packet_size>.\n"
			"    Must follow after <packet_size> option to be effective.\n");
	fprintf(stderr, "  default <num_flows> is 0. (0 = infinite)\n");
	fprintf(stderr, "  default <randomize_flows> is 1. (0 = off)\n");
	fprintf(stderr, "  default <ip version> is 4. (6 = ipv6)\n");
	fprintf(stderr, "  default <latency> is 0. (1 = on)\n");
	fprintf(stderr, "  default <loop count> is 1. (only valid for latency mesaurement)\n");
	fprintf(stderr, "  default <seconds> is 0. (0 = infinite)\n");
	fprintf(stderr, "  default <offered throughput> is maximum possible. (Gbps including Ethernet overheads)\n");
	fprintf(stderr, "  default <neighbor config file> is ./neighbors.conf\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int num_packets = 0;
	int chunk_size = 64;
	int packet_size = 60;
	int min_packet_size = packet_size;
	int num_flows = 0;
	int loop_count = 1;
	char neighbor_conf_filename[MAX_PATH] = "neighbors.conf";
	
	int i;

	ip_version = 4;

	struct timeval begin, end;

	/* Initialization. */

	num_cpus = ps_get_num_cpus();
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	assert(num_devices != -1);
	assert(num_devices > 0);

	/* Argument parsing. */

	for (i = 1; i < argc; i += 2) {
        if (!strcmp(argv[i], "-i")) {
			int ifindex = -1;
			int j;

			/* Register all devices. */
			if (!strcmp(argv[i + 1], "all")) {
				for (j = 0; j < num_devices; j++)
					devices_registered[j] = j;
				num_devices_registered = num_devices;
				continue;
			}

			/* Or, register one by one. */
			for (j = 0; j < num_devices; j++)
				if (!strcmp(argv[i + 1], devices[j].name))
					ifindex = j;

			if (ifindex == -1) {
				fprintf(stderr, "device %s does not exist!\n", 
						argv[i + 1]);
				exit(1);
			}

			for (j = 0; j < num_devices_registered; j++)
				if (devices_registered[j] == ifindex) {
					fprintf(stderr, "device %s is registered more than once!\n",
							argv[i + 1]);
					exit(1);
				}

			devices_registered[num_devices_registered] = ifindex;
			num_devices_registered ++;
		} 
		/// pcap_replaying
        else if (!strcmp(argv[i], "--loop")) {
			pcap_looping = true;
            if ( !mode_pcap_replaying || mode_pkt_gen)
               print_usage(argv[0]); 
			i--;
		} else if (!strcmp(argv[i], "--pcap")) {
            if (mode_pkt_gen)
               print_usage(argv[0]); 
			mode_pcap_replaying = true;
			strncpy(pcap_filename, argv[i + 1], MAX_PATH);
			assert((strnlen(pcap_filename, MAX_PATH) > 0));
		///
		} else {
            if (mode_pcap_replaying == true) {
                fprintf(stderr, "Currently some options can't be used with pcap replaying mode. Check usage.\n");
                print_usage(argv[0]);
            }
            mode_pkt_gen = true;
 
            if (!strcmp(argv[i], "-n")) {
                num_packets = atoi(argv[i + 1]);
                assert(num_packets >= 0);
                if (num_packets < num_cpus / num_devices)
                    fprintf(stderr, "WARNING: Too few packets would not utilize some interfaces.\n");
            } else if (!strcmp(argv[i], "-s")) {
                chunk_size = atoi(argv[i + 1]);
                assert(chunk_size >= 1 && chunk_size <= PS_MAX_CHUNK_SIZE);
            } else if (!strcmp(argv[i], "-p")) {
                packet_size = atoi(argv[i + 1]);
                min_packet_size = packet_size;
                assert(packet_size >= 60 && packet_size <= 1514);
            } else if (!strcmp(argv[i], "--min-pkt-size")) {
                min_packet_size = atoi(argv[i + 1]);
                assert(min_packet_size >= 60 && min_packet_size <= packet_size);
            } else if (!strcmp(argv[i], "-f")) {
                num_flows = atoi(argv[i + 1]);
                assert(num_flows >= 0 && num_flows <= MAX_FLOWS);
            } else if (!strcmp(argv[i], "-r")) {
                randomize_flows = atoi(argv[i + 1]);
                assert(randomize_flows == false || randomize_flows == true);
            } else if (!strcmp(argv[i], "-v")) {
                ip_version = atoi(argv[i + 1]);
                assert(ip_version == 4 || ip_version == 6);
            } else if (!strcmp(argv[i], "-l")) {
                latency_measure = atoi(argv[i + 1]);
                assert(latency_measure == 0 || latency_measure == 1);
                if (latency_measure)
                    magic_number = (uint32_t)ps_rdtsc();
            } else if (!strcmp(argv[i], "-c")) {
                loop_count = atoi(argv[i + 1]);
                assert(loop_count >= 1);
            } else if (!strcmp(argv[i], "-t")) {
                time_limit = atoi(argv[i + 1]);
                assert(time_limit >= 0);
            } else if (!strcmp(argv[i], "-g")) {
                offered_throughput = atof(argv[i + 1]);
                assert(offered_throughput > 0);
            } else if (!strcmp(argv[i], "--debug")) {
                debug = true;
                i--;
            } else if (!strcmp(argv[i], "--neighbor-conf")) {
                strncpy(neighbor_conf_filename, argv[i + 1], MAX_PATH);
                assert(strnlen(neighbor_conf_filename, MAX_PATH) > 0);
            } else { 
                print_usage(argv[0]);
            }
        }
	}

	if (!randomize_flows && num_flows == 0) {
		fprintf(stderr, "Number of flows must be specified when you use -r option (non-random dest address).\n");
		exit(1);
	}
	if (offered_throughput > 0 && min_packet_size != packet_size) {
		fprintf(stderr, "Throughput regulation for random sized packets is not supported yet.\n");
		exit(1);
	}

	if (num_devices_registered == 0) {
		fprintf(stderr, "No devices registered!\n");
		print_usage(argv[0]);
	}

	/* Read neighbor configuration from file.
	 * We currently do not use IP addresses since experimenting a router uses random IP
	 * addresses.  (It's for correctness test in the future.) */

	FILE *f = fopen(neighbor_conf_filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Cannot open the neighbor configuration file \"%s\".\n", neighbor_conf_filename);
		exit(1);
	}
	num_neighbors = 0;
	char *eth_straddr = (char *)malloc(sizeof(char) * 32);
	char *ipv4_straddr = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
	char *ipv6_straddr = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
	if (ip_version == 4) {
		while (EOF != fscanf(f, "%s %s", eth_straddr, ipv4_straddr) && num_neighbors < PS_MAX_DEVICES) {
			assert(NULL != ether_aton_r(eth_straddr, (struct ether_addr *) &neighbor_ethaddrs[num_neighbors]));

			// Note: inet_addr() is defined in the glibc header netinet/in.h, but this header
			// conflicts with the kernel header linux/ipv6.h.
			// TODO: implement IP address parsing.
			//neighbor_ipv4addrs[num_neighbors] = NTOHL(inet_addr(ipv4_straddr));
			num_neighbors++;
		}
	} else if (ip_version == 6) {
		while (EOF != fscanf(f, "%s %s", eth_straddr, ipv6_straddr) && num_neighbors < PS_MAX_DEVICES) {
			assert(NULL != ether_aton_r(eth_straddr, (struct ether_addr *) &neighbor_ethaddrs[num_neighbors]));

			// TODO: implement IP address parsing.
			num_neighbors++;
		}
	}
	free(eth_straddr);
	free(ipv4_straddr);
	free(ipv6_straddr);
	fclose(f);
	/* Currently we only permit the 1-to-1 wired configuration for simplicity.
	 * To avoid ambiguous mapping of source-destination interfaces, it is forced to have the
	 * same number of neighbors and registered devices. */
	/* TODO: make it possible arbitrary source-destination interface mappings. */
	assert(num_neighbors >= num_devices_registered);

	/// pcap_replaying: whole pcap file is allocated to memory & indexed before replaying starts
	if (mode_pcap_replaying) {
		preprocess_pcap_file();
	}
	///
 
	/* Show the configuration. */

	printf("# of CPUs = %d\n", num_cpus);
	printf("# of packets = %d\n", num_packets);
	printf("chunk size = %d\n", chunk_size);
	printf("packet size = %d\n", packet_size);
	printf("min. packet size = %d\n", min_packet_size);
	printf("# of flows = %d\n", num_flows);
	printf("randomize flows = %d\n", randomize_flows);
	printf("ip version = %d\n", ip_version);
	printf("latency measure = %d\n", latency_measure);
	printf("loop count = %d\n", loop_count);
	printf("offered throughput = %.2f Gbps\n", offered_throughput);
	printf("time limit = %d\n", time_limit);

	printf("interfaces: ");
	for (i = 0; i < num_devices_registered; i++) {
		if (i > 0)
			printf(", ");
		printf("%s", devices[devices_registered[i]].name);
	}
	printf("\n");
	
	printf("----------\n");

	/* Fork and send packets. */

	if (num_flows > 0)
		srand(time(NULL));

	assert(gettimeofday(&begin, NULL) == 0);

	for (my_cpu = 0; my_cpu < num_cpus; my_cpu++) {
		int ret = fork();
		assert(ret >= 0);

		if (ret == 0) { /* Child processes generate packets. */
			ps_bind_cpu(my_cpu);
			signal(SIGINT, handle_signal);

			send_packets(num_packets ? : LONG_MAX, chunk_size,
					packet_size,
					min_packet_size,
					num_flows,
					loop_count);
			return 0;
		}
	}

	signal(SIGINT, SIG_IGN);

	while (1) {
		int ret = wait(NULL);
		if (ret == -1 && errno == ECHILD)
			break;
	}

	/// pcap_replaying
	if (mode_pcap_replaying) {
		if (pcap_alloc_file != 0) {
			free(pcap_alloc_file);
			pcap_alloc_file = 0;
		}
	}
	///

	assert(gettimeofday(&end, NULL) == 0);

	printf("----------\n");
	printf("%.2f seconds elapsed\n", 
			((end.tv_sec - begin.tv_sec) * 1000000 +
			 (end.tv_usec - begin.tv_usec))
			/ 1000000.0);

	return 0;
}

