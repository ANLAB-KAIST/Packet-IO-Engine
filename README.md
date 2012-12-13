# Packet I/O Engine

Packet I/O Engine is a high-performance batching-oriented device driver for Intel 82598/82599-based network interface cards.
This program is based on Intel IXGBE driver (version 2.0.38.2), but heavily modified for throughput-oriented user-level applications.
The modifications include batch processing, huge packet buffer, aggressive software prefetch, etc.

See more details at [the homepage for Packet I/O Engine](http://shader.kaist.edu/packetshader/io_engine/index.html) and [the homepage for PacketShader](http://shader.kaist.edu/packetshader/index.html).

## Notice

Currently this project is mainly maintained by Joongi Kim.
However, our responses to new issues will be delayed for a while since he is doing an internship in Microsoft Research until February 2013.
It is difficult to actively debug and improve the code in the meanwhile.
We appreciate all the emails and issue reports you have sent to us, but we're sorry that we could not promptly reply to you.

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

