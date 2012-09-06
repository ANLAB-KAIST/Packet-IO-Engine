#!/usr/bin/env python
# This script requires Python 2.6 or higher.

from __future__ import print_function, with_statement
import os
import sys
import subprocess
import re

_exec_cache = {}

def execute(cmd, cache=False):
    global _exec_cache
    if cache and cmd in _exec_cache:
        return _exec_cache[cmd]
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        result = proc.communicate()[0]
        if cache:
            _exec_cache[cmd] = result
        return result
    except:
        return None

def find_iface_node(name):
    ifnode = -1
    for line in execute('ethtool -i {0}'.format(ifname), cache=True).splitlines():
        if line.startswith('bus-info:'):
            bus_location = line.split(':', 1)[1].strip()
            p1, p2, _ = bus_location.split(':')
            bus_prefix = '{0}:{1:02x}'.format(p1, int(p2, 16) & 0xf0)
            bus_affinity = execute('cat /sys/devices/pci{0}/pci_bus/{0}/cpuaffinity'.format(bus_prefix), cache=True).strip()
            for node in range(num_nodes):
                node_affinity = execute('cat /sys/devices/system/node/node{0}/cpumap'.format(node), cache=True).strip()
                if node_affinity == bus_affinity:
                    ifnode = node
                    break
    assert ifnode != -1
    return ifnode

if os.getuid() != 0:
    print('You must be root!', file=sys.stderr)
    sys.exit(1)

num_cpus = int(execute('cat /proc/cpuinfo | grep -c processor').strip())

if len(sys.argv) < 3:
    print('usage: %s <interface name> <#intefaces>' % sys.argv[0])
    sys.exit(1)

ifname = sys.argv[1]
num_devices = int(sys.argv[2])

intrmap = execute('cat /proc/interrupts | grep -i %s-rx-' % ifname).strip().split('\n')
num_nodes = int(execute('cat /proc/cpuinfo | grep \'physical id\' | sort -u | wc -l'))

for intr in intrmap:
    if intr:
        irq = int(re.search(r'^\s*(\d+):', intr).group(1))
        queue = int(re.search(r'-(\d+)$', intr).group(1))
        cpu = (queue * num_nodes) + find_iface_node(ifname)
        print('echo %x > /proc/irq/%d/smp_affinity' % (1 << cpu, irq))
        execute('echo %x > /proc/irq/%d/smp_affinity' % (1 << cpu, irq))
    else:
        print('The device {0} is not found on the interrupt table!'.format(ifname), file=sys.stderr)
        break
