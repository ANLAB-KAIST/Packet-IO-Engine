#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
 
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "psio.h"

static int k2ps_ifindex_map[PS_MAX_DEVICES];
static struct ps_device device_list[PS_MAX_DEVICES];

int ps_list_devices(struct ps_device *devices)
{
	struct ps_handle handle;
	int ret, i;

	if (ps_init_handle(&handle))
		return -1;

	ret = ioctl(handle.fd, PS_IOC_LIST_DEVICES, devices);
	for (i = 0; i < ret; i++) {
		k2ps_ifindex_map[devices[i].kifindex] = i;
		device_list[i] = devices[i];
	}

	ps_close_handle(&handle);

	return ret;
}

int ps_init_handle(struct ps_handle *handle)
{
	int i;

	memset(handle, 0, sizeof(struct ps_handle));

	handle->fd = open("/dev/packet_shader", O_RDWR);
	if (handle->fd == -1)
		return -1;

	for (i = 0; i < PS_MAX_DEVICES; i++)
		k2ps_ifindex_map[i] = -1;
	return 0;
}

void ps_close_handle(struct ps_handle *handle)
{
	close(handle->fd);
	handle->fd = -1;
}

int ps_attach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	return ioctl(handle->fd, PS_IOC_ATTACH_RX_DEVICE, queue);
}

int ps_detach_rx_device(struct ps_handle *handle, struct ps_queue *queue)
{
	return ioctl(handle->fd, PS_IOC_DETACH_RX_DEVICE, queue);
}

int ps_alloc_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	memset(chunk, 0, sizeof(*chunk));

	chunk->info = (struct ps_pkt_info *)malloc(
			sizeof(struct ps_pkt_info) * PS_MAX_CHUNK_SIZE);
	if (!chunk->info)
		return -1;

	chunk->buf = (char *)mmap(NULL, PS_MAX_PACKET_SIZE * PS_MAX_CHUNK_SIZE, 
			PROT_READ | PROT_WRITE, MAP_SHARED,
			handle->fd, 0);
	if ((long)chunk->buf == -1)
		return -1;

	return 0;
}

void ps_free_chunk(struct ps_chunk *chunk)
{
	free(chunk->info);
	munmap(chunk->buf, PS_MAX_PACKET_SIZE * PS_MAX_CHUNK_SIZE);

	chunk->info = NULL;
	chunk->buf = NULL;
}

int ps_recv_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	int cnt;

	cnt = ioctl(handle->fd, PS_IOC_RECV_CHUNK, chunk);
	if (cnt > 0) {
		int i;
		int ifindex = chunk->queue.ifindex;

		handle->rx_chunks[ifindex]++;
		handle->rx_packets[ifindex] += cnt;

		for (i = 0; i < cnt; i++)
			handle->rx_bytes[ifindex] += chunk->info[i].len;
	}

	return cnt;
}

/* Send the given chunk to the modified driver. */
int ps_send_chunk(struct ps_handle *handle, struct ps_chunk *chunk)
{
	int cnt;

	cnt = ioctl(handle->fd, PS_IOC_SEND_CHUNK, chunk);
	if (cnt >= 0) {
		int i;
		int ifindex = chunk->queue.ifindex;

		handle->tx_chunks[ifindex]++;
		handle->tx_packets[ifindex] += cnt;

		for (i = 0; i < cnt; i++)
			handle->tx_bytes[ifindex] += chunk->info[i].len;
	}

	return cnt;
}

int ps_slowpath_packet(struct ps_handle *handle, struct ps_packet *packet)
{
	return ioctl(handle->fd, PS_IOC_SLOWPATH_PACKET, packet);
}

int ps_alloc_view_chunk(struct ps_chunk *view_chunk, struct ps_chunk *src_chunk, bool copy_info)
{
	memset(view_chunk, 0, sizeof(*view_chunk));

	view_chunk->info = (struct ps_pkt_info *) malloc(
			sizeof(struct ps_pkt_info) * PS_MAX_CHUNK_SIZE);
	if (!view_chunk->info)
		return -1;

	if (copy_info) {
		memcpy(view_chunk->info, src_chunk->info, sizeof(struct ps_pkt_info) * PS_MAX_CHUNK_SIZE);
		view_chunk->cnt = src_chunk->cnt;
		view_chunk->queue = src_chunk->queue;
	} else {
		memset(view_chunk->info, 0, sizeof(struct ps_pkt_info) * PS_MAX_CHUNK_SIZE);
		view_chunk->cnt = 0;
		view_chunk->queue.qidx = -1;
		view_chunk->queue.ifindex = -1;
	}

	view_chunk->buf = src_chunk->buf;

	return 0;
}

int ps_free_view_chunk(struct ps_chunk *view_chunk)
{
	view_chunk->cnt = 0;
	free(view_chunk->info);
	view_chunk->info = NULL;
	view_chunk->buf = NULL;
	return 0;
}

int ps_to_psifindex(int kifindex)
{
	return k2ps_ifindex_map[kifindex];
}

int ps_to_kifindex(int psifindex)
{
	return device_list[psifindex].kifindex;
}
