#! /usr/bin/env python3

# A simple live monitoring script for throughputs and other statistics
# using ethtool. A fully utilized 10 Gbps link showes about 14.2M pps
# with 64 B packets.

# The best environment for this script is Python 3.x or higher.
# However, you can run it even on Python 2.6 depending on your system.
# The primary reason to use 3.x versions is "," formatting of numbers.
# If you do not need that, just don't use '-f' option.
# To see the result values in a naturally sorted order, use Python 2.7
# or higher (due to OrderedDict).

# Note that this script may have some overheads, so please terminate it
# when you do serious performance measurements requiring high accuracy.

from __future__ import print_function
import sys, os
import time
import copy
import subprocess
import multiprocessing
try:
    from collections import OrderedDict
except ImportError:
    OrderedDict = None
from optparse import OptionParser

def execute(cmd, check_returncode=False):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if check_returncode and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return stdout.decode('ascii')

def get_stats(dev):
    lines = execute('ethtool -S {0}'.format(dev), True).splitlines()[1:]
    if OrderedDict is None:
        ret = {}
    else:
        ret = OrderedDict()

    for line in lines:
        line = line.strip()
        key, value = line.split(': ')
        ret[key.strip()] = int(value)
    return ret

if __name__ == '__main__':

    if os.geteuid() != 0:
        print('You msut be root!', file=sys.stderr)
        sys.exit(1)

    oparser = OptionParser()
    oparser.add_option('-i', '--interval', dest='interval', default=1.0, type=float,
                       help='sets the update interval in seconds (default: 1.0)')
    oparser.add_option('-v', '--verbose', dest='verbose', action='store_true', default=False,
                       help='shows all statistics even if they are not changed during an interval.')
    oparser.add_option('-f', '--format-numbers', dest='format_numbers', action='store_true', default=False,
                       help='formats numbers with commas and human-readable units for monitoring purpose.')
    opts, args = oparser.parse_args()

    num_cpus = multiprocessing.cpu_count()
    interested_fields = set('tx_queue_{0}_packets'.format(i) for i in range(num_cpus)) | \
                        set('rx_queue_{0}_packets'.format(i) for i in range(num_cpus)) | \
                        set('tx_queue_{0}_bytes'.format(i) for i in range(num_cpus)) | \
                        set('rx_queue_{0}_bytes'.format(i) for i in range(num_cpus)) | \
                        set(('tx_bytes', 'rx_bytes', 'tx_errors', 'rx_errors',
                            'tx_packets', 'rx_packets', 'tx_dropped', 'rx_dropped',
                            'rx_missed_errors'))
    last_stats = {}
    stats = {}

    if opts.format_numbers:
        if sys.version_info < (3, 1):
            print('Comman-separated number formatting requires Python 3.1 or higher.', file=sys.stderr)
            sys.exit(1)
        int_format = '{0:>16,d}'
    else:
        int_format = '{0:>16d}'

    devs = []
    print()
    while len(devs) == 0:
        devs = execute('ifconfig -s | grep xge | awk \'{print $1}\'').splitlines()
        print("\033[2K\033[1Ano xge devices found, waiting...")
        time.sleep(1)
    for dev in devs:
        last_stats[dev] = get_stats(dev)
    last_timestamp = time.time()

    try:
        while True:
            strbuf = []
            strbuf.append('\033[2J\033[0;0H')
            strbuf.append(time.ctime() + '\n')
            strbuf.append('Thrughputs per second:\n')
            strbuf.append('{0:<20}'.format('FIELD'))
            try:
                for dev in devs:
                    strbuf.append('{0:>16}'.format(dev))
                    stats[dev] = get_stats(dev)
            except subprocess.CalledProcessError as e:
                if e.returncode == 71:  # means "No such device", maybe reinstalling the module.
                    time.sleep(0.5)
                    continue
                else:
                    print("Unexpected ethtool return code: {0}".format(e.returncode), file=sys.stderr)
                    print(e.output, file=sys.stderr)
                    sys.exit(1)
            if len(devs) >= 2:
                strbuf.append('{0:>16}'.format('TOTAL'))
            strbuf.append('\n')

            timestamp = time.time()
            interval = timestamp - last_timestamp

            keys = filter(lambda k: k in interested_fields, stats[devs[0]].keys())

            for key in keys:
                is_diff = False

                for dev in devs:
                    if stats[dev][key] != last_stats[dev][key]:
                        is_diff = True

                if opts.verbose or is_diff:
                    strbuf.append('{0:<20}'.format(key))
                    total_diff = 0
                    for dev in devs:
                        diff = stats[dev][key] - last_stats[dev][key]
                        diff /= interval
                        total_diff += diff
                        strbuf.append(int_format.format(int(diff)))
                    if len(devs) >= 2:
                        strbuf.append(int_format.format(int(total_diff)))
                    strbuf.append('\n')

            print(''.join(strbuf))
            time.sleep(opts.interval)
            last_stats = copy.copy(stats)
            last_timestamp = timestamp
    except KeyboardInterrupt:
        print()
# vim: ts=8 sts=4 sw=4 et fo=croql
