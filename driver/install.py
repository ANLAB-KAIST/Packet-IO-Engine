#!/usr/bin/env python
# This script requires Python 2.6 or higher.

from __future__ import print_function, with_statement
import sys
import os, socket
import subprocess
import time
from optparse import OptionParser

# Whereever this script is executed, it runs inside its directory.
# (It's for convenience)
base_path = os.path.abspath(os.path.dirname(__file__))

def execute(cmd, check_returncode=False):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if check_returncode and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return stdout

def get_num_interfaces():
    num_82598 = int(execute('lspci | grep -c 82598').strip())
    num_82599 = int(execute('lspci | grep -c 82599').strip())
    return num_82598 + num_82599

def get_num_cpus():
    return int(execute('cat /proc/cpuinfo | grep -c processor').strip())

def check_all_links_up():
    output = execute('ifconfig -s | grep xge')
    all_links_up = True
    for line in output.split('\n'):
        flags = line.strip().split()
        if len(flags) == 0:
            continue
        if 'R' not in flags[-1]:
            all_links_up = False
    return all_links_up

def validate_ipaddr(addr):
    try:
        socket.inet_aton(addr)
    except socket.error:
        return False
    else:
        return addr.count('.') == 3

if __name__ == '__main__':

    if os.geteuid() != 0:
        print('You must be root!', file=sys.stderr)
        sys.exit(1)

    oparser = OptionParser(usage='%prog [OPTIONS] #RX_QUEUES #TX_QUEUES',
                           epilog='You can specify 0 instead of actual number of RX/TX queues to allocate one queue for each core.')
    oparser.add_option('--itr', type='int', dest='itr', default=956,
                       help='sets the interrupt throttling rate.  (default: 956)')
    oparser.add_option('-p', '--postfix', type='int', dest='postfix', default=1,
                       help='sets the postfix of IP address allocated to the 10G NICs.  If x is the postfix and n is the NIC index, the IP addresses will be {IP_PREFIX}.n.x.  (default: 1)')
    oparser.add_option('--skip-check', dest='skip_check', action='store_true', default=False,
                       help='skips checking the link state after driver installation.  (default: False)')
    oparser.add_option('--ip-prefix', dest='ip_prefix', default='10.42',
                       help='sets the prefix of IP address.  (default: 10.42)')
    opts, args = oparser.parse_args()

    if len(args) < 2:
        oparser.print_help()
        sys.exit(1)

    assert opts.postfix >= 1 and opts.postfix <= 254
    num_rx_queues = int(args[0])
    num_tx_queues = int(args[1])
    assert 0 <= num_rx_queues <= 16
    assert 0 <= num_tx_queues <= 16
    assert validate_ipaddr(opts.ip_prefix + '.0.0')

    os.chdir(base_path)

    if not (os.path.exists('./ps_ixgbe.ko')):
        print('The compiled kernel module is not found.', file=sys.stderr)
        sys.exit(1)

    num_ifs = get_num_interfaces()
    num_cpus = get_num_cpus()

    execute('lsmod | grep ^ixgbe > /dev/null && sudo rmmod ixgbe')
    execute('lsmod | grep ^ps_ixgbe > /dev/null && sudo rmmod ps_ixgbe')
    execute('insmod ./ps_ixgbe.ko RXQ=%s TXQ=%s InterruptThrottleRate=%s' %
            (','.join([str(num_rx_queues)] * num_ifs),
             ','.join([str(num_tx_queues)] * num_ifs),
             ','.join([str(opts.itr)] * num_ifs))
            , True)

    time.sleep(3)

    for i in range(num_ifs):
        ifname = 'xge%d' % i
        print('Setting {0}...'.format(ifname))

        execute('ethtool -A %s autoneg off rx off tx off' % ifname)
        execute('ifconfig %s %s.%d.%s netmask 255.255.255.0 mtu 1500' % (ifname, opts.ip_prefix, i, opts.postfix), True)

        print('OK')
        print(execute('./affinity.py %s %d' % (ifname, num_ifs), True).strip())

    execute('rm -f /dev/packet_shader')
    execute('mknod /dev/packet_shader c 1010 0')
    execute('chmod 666 /dev/packet_shader')

    if not opts.skip_check:
        print('Waiting for all links up...')
        time.sleep(2)
        check_count = 0
        warning_printed = False
        while not check_all_links_up():
            time.sleep(1)
            check_count += 1
            if check_count > 10 and not warning_printed:
                print('  If this step takes too long,\n' + \
                      '   1) stop the script and try to reinstall the driver.\n' + \
                      '   2) check if the cables are tightly connected.\n')
                warning_printed = True

    print('Ready.')
