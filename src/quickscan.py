#!/usr/bin/env python

import logging
import argparse
from scapy.all import sr1, IP, TCP
import time
import json
from tabulate import tabulate
from multiprocessing.pool import ThreadPool
import random


FORMAT = "%(asctime)s : %(name)s : %(levelname)-8s : %(message)s"
logging.basicConfig(format=FORMAT)
# logging.getLogger('scapy').setLevel(logging.WARNING)
log = logging.getLogger('quickscan')


TEST_RUN = True
TCP_FLAGS_MAPPING = {
    'S': 'SYN',
    'A': 'ACK',
    'F': 'FIN',
    'R': 'RST',
    'P': 'PSH',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}
THREAD_COUNT = 8


def _build_scan_targets(input_targets:list):
    """
    Given some information of hosts, ports, other information, turn that into a list we can use to run scans with

    Examples:
        Input target:
            [
                {'host': '10.1.0.1', 'port': 22, 'protocol': 'tcp'},
                {'host': '10.1.0.2', 'port': '*', 'protocol': 'tcp'}
            ]
        Resulting target:
            [
                ['10.1.0.1', 22, 'tcp'],
                ['10.1.0.2', 1, 'tcp'],
                ['10.1.0.2', 2, 'tcp'],
                ['10.1.0.2', 3, 'tcp'],
                ...
            ]

    TODO: interpret wildcars, port ranges, etc. into discrete targets
    """
    built_targets = []
    for target in input_targets:
        new_targets = []

        host = target['host']
        port = target['port']
        protocol = target['protocol']

        if type(port) is str:
            if port == '*':
                new_targets = [[host, port, protocol] for port in range(1, 2**16)]  # Ports 1-65535
            elif '-' in port:
                start, end = port.split('-')
                start = int(start)
                end = int(end)
                new_targets = [[host, port, protocol] for port in range(start, end + 1)]  # Ports 1-65535
        else:
            new_targets = [[host, port, protocol]]

        built_targets += new_targets

    return built_targets


def _scan_target(host:str, port:int, protocol:str) -> dict:
    """
    Run scan on a particular combination
    """
    target = f"{host}:{port}/{protocol}"
    log.debug(f"Scanning {target}")

    # Do the scan
    # TODO: set a timeout to make sure it scans fast even if no response
    # TODO: randomized source port
    sport = random.randrange(32768, 60999)
    scan_response_packet = sr1(IP(dst=host) / TCP(sport=sport, dport=port, flags="S"), verbose=False)
    # tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
    # tcpResponse = sr1(tcpRequest,timeout=1,verbose=0)
    # log.debug(f"scan_response_packet: {scan_response_packet.summary()}")

    # Interpret results
    tcp = scan_response_packet.getlayer(TCP)
    flags = tcp.flags
    flags_interpreted = [TCP_FLAGS_MAPPING[flag] for flag in flags]
    # log.debug(f"Flags: {flags_interpreted}")

    # Naive interpretation of open port
    status = 'unknown'
    if flags.S:
        status = 'open'
    elif flags.R:
        status = 'closed'
    is_open = True if flags.S and flags.A else False
    if is_open:
        log.info(f"Open port found: {target}")

    result = {
        'target': target,
        'open': is_open,
        'status': status,
        'flags': flags_interpreted,
        'packet': scan_response_packet
    }

    return result


def _submit_scan_job(targets:list):
    """
    Run a multithreaded scan across all targets specified
    """
    pool = ThreadPool(processes=THREAD_COUNT)
    async_result = pool.starmap_async(_scan_target, targets)
    results = async_result.get()

    return results


def parse_results():
    """
    Given results of scan, make sense of it with with hosts have what ports open

    Placeholder, may not be necessary
    """
    pass


def _print_table(results:list):
    headers = ['target', 'status', 'open', 'flags']
    table = []
    for entry_dict in results:
        entry_list = [entry_dict[h] for h in headers]
        table.append(entry_list)
    print(tabulate(table, headers, tablefmt='pipe'))  # markdown table


def create_report_text():
    pass


def create_report_json():
    # print(json.dumps(results, indent=4))
    pass


def create_report_csv():
    pass


def run_scan(targets:list, output_terminal:bool=True, output_text:bool=False, output_json:bool=False, output_csv:bool=False) -> list:
    """
    Do the thing
    """
    log.debug(f"Provided {len(targets)} targets: {targets}")
    built_targets = _build_scan_targets(targets)
    log.debug(f"Built into {len(built_targets)} targets: {built_targets}")

    log.info(f"Starting scan on {len(built_targets)} targets")
    start = time.time()
    results = _submit_scan_job(built_targets)
    end = time.time()

    elapsed = end - start
    log.info(f"Scan time: {elapsed:.5f} seconds")

    _print_table(results)

    if output_text:
        pass
    if output_json:
        pass
    if output_csv:
        pass

    return results


def basic_test():
    targets = []
    known_open_local = {
        'host': '10.1.0.1',
        'port': 22,
        'protocol': 'tcp'
    }
    known_closed_local = {
        'host': '10.1.0.1',
        'port': 12345,
        'protocol': 'tcp'
    }
    example_http = {  # example.com
        'host': '93.184.216.34',
        'port': 80,
        'protocol': 'tcp'
    }
    example_https = {  # example.com
        'host': '93.184.216.34',
        'port': 443,
        'protocol': 'tcp'
    }
    google_http = {  # google.com
        'host': '142.250.72.206',
        'port': 80,
        'protocol': 'tcp'
    }
    google_https = {  # google.com
        'host': '142.250.72.206',
        'port': 443,
        'protocol': 'tcp'
    }
    range_target = {
        'host': '10.1.0.1',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    wildcard_target = {
        'host': '10.1.0.1',
        'port': '*',
        'protocol': 'tcp'
    }

    # targets.append(known_open_local)
    # targets.append(known_closed_local)
    # targets.append(example_http)
    # targets.append(example_https)
    # targets.append(google_http)
    # targets.append(google_https)
    targets.append(range_target)
    # targets.append(wildcard_target)

    results = run_scan(targets)

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='Set logging level to DEBUG')
    args = parser.parse_args()

    log.setLevel(logging.DEBUG) if args.debug else log.setLevel(logging.INFO)

    log.info('Starting')

    if TEST_RUN:
        results = basic_test()
    else:
        # TODO: take in user input
        pass

    log.info('Complete')
