#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "../include/ps.h"

int ps_list_devices(struct ps_device *devices)
{
	struct ps_handle handle;
	int ret;

	if (ps_init_handle(&handle))
		return -1;

	ret = ioctl(handle.fd, PS_IOC_LIST_DEVICES, devices);
	
	ps_close_handle(&handle);

	return ret;
}

int ps_init_handle(struct ps_handle *handle)
{
	memset(handle, 0, sizeof(struct ps_handle));

	handle->fd = open("/dev/packet_shader", O_RDWR);
	if (handle->fd == -1)
		return -1;

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
			sizeof(struct ps_pkt_info) * MAX_CHUNK_SIZE);
	if (!chunk->info)
		return -1;

	chunk->buf = (char *)mmap(NULL, MAX_PACKET_SIZE * MAX_CHUNK_SIZE, 
			PROT_READ | PROT_WRITE, MAP_SHARED,
			handle->fd, 0);
	if ((long)chunk->buf == -1)
		return -1;

	return 0;
}

void ps_free_chunk(struct ps_chunk *chunk)
{
	free(chunk->info);
	munmap(chunk->buf, MAX_PACKET_SIZE * MAX_CHUNK_SIZE);

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
