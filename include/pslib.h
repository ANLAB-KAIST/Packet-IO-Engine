#ifndef __PSLIB_H__
#define __PSLIB_H__

//#include "ps_common.h"
#ifdef BEGIN_C_DECLS
#undef BEGIN_C_DECLS
#endif

#ifdef END_C_DECLS
#undef END_C_DECLS
#endif

#ifdef __cplusplus
#define BEGIN_C_DECLS extern "C" {
#define END_C_DECLS }
#else
#define BEGIN_C_DECLS
#define END_C_DECLS
#endif

#ifndef ps_attr_align_64
#define ps_attr_align_64	__attribute__((aligned (64)))
#endif

BEGIN_C_DECLS

/*
 * Constant for io_engine and corresponding libraries only
 */
enum {
	PS_MAX_CPUS = 16,
	PS_MAX_DEVICES = 16,
	PS_MAX_queueS = 64,
	PS_MAX_BUFS = 16,
	PS_MAX_PACKET_SIZE = 2048,
	PS_MAX_CHUNK_SIZE = 4096,

	PS_CHECKSUM_RX_UNKNOWN = 0,
	PS_CHECKSUM_RX_GOOD = 1,
	PS_CHECKSUM_RX_BAD = 2,
};

#ifdef __KERNEL__

#define PS_MAJOR 1010
#define PS_NAME "packet_shader"

#define MAX_BUFS 256

struct ps_attr_align_64 ps_context {
	struct semaphore sem;

	wait_queue_head_t wq;

	int num_attached;
	struct ixgbe_ring *rx_rings[PS_MAX_queueS];
	int next_ring;

	struct ps_pkt_info *info;
	/* char *buf; */

	int num_bufs;
	int buf_refcnt[MAX_BUFS];
	char *kbufs[MAX_BUFS];
	char __user *ubufs[MAX_BUFS];
};

#else	/* end of __KERNEL__ */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <linux/types.h>

#define __user
#define IFNAMSIZ 16
#define ETH_ALEN 6

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne      1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	    /* Since the input registers which are loaded with iph and ih
	       are modified, we must also specify them as outputs, or gcc
	       will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	       : "memory");
	return (__sum16)sum;
}

#endif	/* __KERNEL__ */

struct ps_device {
	char name[IFNAMSIZ];
	char dev_addr[ETH_ALEN];
	uint32_t ip_addr;	/* network order */

	/* NOTE: this is different from kernel's internal index */
	int ifindex;

	/* This is kernel's ifindex. */
	int kifindex;

	/* The closest NUM node. */
	int numa_node;

	int num_rx_queues;
	int num_tx_queues;
};

struct ps_queue {
	int ifindex;
	int qidx;
};

#define MAX_PACKET_SIZE	2048
#define MAX_CHUNK_SIZE	4096

#define PS_CHECKSUM_RX_UNKNOWN 	0
#define PS_CHECKSUM_RX_GOOD	1
#define PS_CHECKSUM_RX_BAD 	2

/**
 * Packet metadata for chunks.
 * Note that this struct is copied everytime when it crosses the
 * user/kernel boundary.
 */
struct ps_pkt_info {
	int offset;
	int len;
	uint8_t checksum_rx; /** Stores the result of HW-assisted checksum. */
};

/**
 * A memory-bound packet list with continuous buffer.
 */
struct ps_chunk {

	int cnt;		/** The number of packets to send/recv. */
	int recv_blocking;	/** Indicates the blocking mode. */

	/**
	 * for RX: output (where did these packets come from?)
	 * for TX: input (which interface do you want to xmit?)
	 */
	struct ps_queue queue;

	/**
	 * The list of packet metadata.
	 */
	struct ps_pkt_info __user *info;

	/**
	 * The continuous packet buffer for efficient I/O.
	 * This is allocated using `mmap()` systemcall.
	 */
	char __user *buf;

	int priv;  /** reserved for the pipeline implementation. */
};

/**
 * Metadata for a specific packet, independently.
 */
struct ps_packet {
	int offset;
	int len;
	int arrived_ifindex;  /** Used for the slowpath. */
	char __user *buf;  /** The pointer to the packet frame. */
	int rx_idx;  /** rx_idx to find the RX/TX chunks. */
	// TODO: module-specific annotations?
};

struct ps_neighbor {
	uint8_t ethaddr[ETH_ALEN];
	char ip_version;
	uint8_t ipaddr[16];
	int connected_ifindex;
};


static inline void prefetcht0(void *p)
{
	asm volatile("prefetcht0 (%0)\n\t"
			: 
			: "r" (p)
		    );
}

static inline void prefetchnta(void *p)
{
	asm volatile("prefetchnta (%0)\n\t"
			: 
			: "r" (p)
		    );
}

static inline void memcpy_aligned(void *to, const void *from, size_t len)
{
	if (len <= 64) {
		memcpy(to, from, 64);
	} else if (len <= 128) {
		memcpy(to, from, 64);
		memcpy((uint8_t *)to + 64, (uint8_t *)from + 64, 64);
	} else {
		size_t offset;

		for (offset = 0; offset < len; offset += 64)
			memcpy((uint8_t *)to + offset, 
					(uint8_t *)from + offset, 
					64);
	}
}

#define PS_IOC_LIST_DEVICES 	0
#define PS_IOC_ATTACH_RX_DEVICE	1
#define PS_IOC_DETACH_RX_DEVICE	2
#define PS_IOC_RECV_CHUNK	3
#define PS_IOC_SEND_CHUNK	4
#define PS_IOC_SLOWPATH_PACKET	5

#ifndef __KERNEL__

struct ps_handle {
	int fd;

	uint64_t rx_chunks[PS_MAX_DEVICES];
	uint64_t rx_packets[PS_MAX_DEVICES];
	uint64_t rx_bytes[PS_MAX_DEVICES];

	uint64_t tx_chunks[PS_MAX_DEVICES];
	uint64_t tx_packets[PS_MAX_DEVICES];
	uint64_t tx_bytes[PS_MAX_DEVICES];

	void *priv;
};


int ps_list_devices(struct ps_device *devices);
int ps_init_handle(struct ps_handle *handle);
void ps_close_handle(struct ps_handle *handle);
int ps_attach_rx_device(struct ps_handle *handle, struct ps_queue *queue);
int ps_detach_rx_device(struct ps_handle *handle, struct ps_queue *queue);
int ps_alloc_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
void ps_free_chunk(struct ps_chunk *chunk);
int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk);
int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet);

/**
 * Make a "view" of the given chunk.
 * The view chunk shares the buffer pointer, and may have its own packet
 * information list.
 */
int ps_alloc_view_chunk(struct ps_chunk *view_chunk, struct ps_chunk *src_chunk, bool copy_info);
int ps_free_view_chunk(struct ps_chunk *view_chunk);

int ps_to_psifindex(int kifindex);
int ps_to_kifindex(int psifindex);

#endif

END_C_DECLS

#endif	/* _PSLIB_H_ */
