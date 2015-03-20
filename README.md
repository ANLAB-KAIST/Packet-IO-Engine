# Packet I/O Engine

Packet I/O Engine is a high-performance batch-oriented device driver for Intel 82598/82599-based network interface cards.
This program is based on Intel IXGBE driver (version 2.0.38.2), but heavily modified for throughput-oriented user-level applications.
The modifications include batch processing, huge packet buffer, aggressive software prefetch, and etc.

See more details at [the homepage for Packet I/O Engine](http://shader.kaist.edu/packetshader/io_engine/index.html) and [the homepage for PacketShader](http://shader.kaist.edu/packetshader/index.html).

## Notice

We are no longer actively managing this project as we have migrated our base to Intel DPDK.
However, we are still looking forward to your pull requests and issue reports.

For those who continue to use the packet generator (pspgen), please consider using [pspgen-dpdk](https://github.com/ANLAB-KAIST/pspgen-dpdk) instead.

## Contributors

 * Sangjin Han
 * Keon Jang
 * Seonggu Huh
 * Joongi Kim (current maintainer)

This work is done by cooperation of [ANLAB](http://an.kaist.ac.kr) and [NDSL](http://www.ndsl.kaist.edu) in [KAIST](http://www.kaist.ac.kr).

## Compatibility

The current version can run with Linux kernel 2.6.36 and several prior versions.
We are going to extend the support to Linux kernel 3.x in the near future.

## License

 * GNU Public License, version 2.

