#!/usr/bin/env python

from __future__ import print_function, with_statement
import os
import sys
import subprocess

def execute(cmd):
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        return proc.communicate()[0]
    except:
        return None

if os.getuid() != 0:
    print('You must be root!', file=sys.stderr)
    sys.exit(1)

num_cpus = int(execute('cat /proc/cpuinfo | grep -c processor').strip())

if len(sys.argv) < 3:
    print('usage: %s <interface name> <#intefaces>' % sys.argv[0])
    sys.exit(1)

ifname = sys.argv[1]
num_devices = int(sys.argv[2])

intrmap = execute('cat /proc/interrupts | grep %s-rx-' % ifname).strip().split('\n')
#num_devices = int(execute('ifconfig -s | grep -c xge'))  # this gives incorrect value before "ifconfig up".
num_nodes = int(execute('cat /proc/cpuinfo | grep \'physical id\' | sort -u | wc -l'))

for intr in intrmap:
    if intr:
        irq = int(intr.split()[0][:-1])
        queue = int(intr.split()[-1][-1])

        if num_cpus == 4:
            cpu = queue
        elif num_cpus in (8, 12):
            cpu = queue * 2
            # assume that xge0 ~ xge(1/N-1) is in node 0,
            #             xge(1/N) ~ xge(N) is in node 1.
            #             where N is the number of devices.
            if int(ifname[-1]) >= num_devices / num_nodes:
                cpu += 1
        else:
            assert False, 'PacketShader supports only 4 or 8 core systems currently.'

        print('echo %x > /proc/irq/%d/smp_affinity' % (1 << cpu, irq))
        execute('echo %x > /proc/irq/%d/smp_affinity' % (1 << cpu, irq))
    else:
        print('The device {0} is not found on the interrupt table!'.format(ifname), file=sys.stderr)
        break
