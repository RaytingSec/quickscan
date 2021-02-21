#!/usr/bin/env python

import logging
import argparse
# from scapy.all import sr, sr1, sndrcv, IP, TCP, conf
import time
import json
from tabulate import tabulate
from multiprocessing.pool import ThreadPool
import random
import socket


FORMAT = "%(asctime)s : %(name)s : %(levelname)-8s : %(message)s"
logging.basicConfig(format=FORMAT)
# logging.getLogger('scapy').setLevel(logging.WARNING)
log = logging.getLogger('quickscan')


socket.setdefaulttimeout(100 / 1000)  # Milliseconds to seconds
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
CONFIG = {
    'hide_closed': False,
    'thread_count': 8
}


def _scan_target(host:str, port:int, protocol:str) -> dict:
    """
    Use python socket connections to try checking if port is open

    TODO: would be nice to use the TCP response flags
    """
    target = f"{host}:{port}/{protocol}"
    log.debug(f"Scanning {target}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    status = 'unknown'
    is_open = False
    flags_interpreted = 'na'

    try:
        s.connect((host, port))
        s.close()
        log.info(f"Open port found: {target}")
        status = 'open'
        is_open = True
    except socket.timeout:
        log.debug('timed out')
        status = 'timeout'
    except ConnectionRefusedError:
        status = 'closed'
    except Exception as e:
        log.exception(f"Failed on {target}: {e}")

    return {
        'target': target,
        'open': is_open,
        'status': status,
        'flags': flags_interpreted
    }


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

    TODO: host ranges/cidr would be nice
    """
    built_targets = []
    for target in input_targets:
        new_targets = []

        host = target['host']
        port = target['port']
        protocol = target['protocol']

        if port == '*':
            new_targets = [[host, port, protocol] for port in range(1, 2**16)]  # Ports 1-65535
        elif type(port) is str and '-' in port:
            start, end = port.split('-')
            start = int(start)
            end = int(end)
            new_targets = [[host, port, protocol] for port in range(start, end + 1)]
        else:
            port = int(port)
            new_targets = [[host, port, protocol]]

        built_targets += new_targets

    return built_targets


def _submit_scan_job(targets:list):
    """
    Run a multithreaded scan across all targets specified
    """
    # Attempt to randomize as a jury rigged method of scanning across multiple hosts at once
    random.shuffle(targets)

    pool = ThreadPool(processes=CONFIG['thread_count'])
    async_result = pool.starmap_async(_scan_target, targets)
    results = async_result.get()

    # Un-randomize results
    sorted_results = sorted(results, key=lambda k: k['target'])

    return sorted_results


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
        if CONFIG['hide_closed'] and not entry_dict['open']:
            continue
        entry_list = [entry_dict.get(h, '') for h in headers]
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
    log.debug(f"Built into {len(built_targets)}")

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

    open_targets = [None for result in results if result['open']]
    log.info(f"{len(open_targets)} targets open")

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
    range_target_1 = {
        'host': '10.1.0.1',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    range_target_2 = {
        'host': '10.1.0.2',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    range_target_3 = {
        'host': '10.1.0.3',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    range_target_4 = {
        'host': '10.1.0.24',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    range_target_5 = {
        'host': '10.1.0.25',
        'port': '1-1000',
        'protocol': 'tcp'
    }
    range_target_6 = {
        'host': '10.1.0.27',
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
    targets.append(range_target_1)
    targets.append(range_target_2)
    targets.append(range_target_3)
    targets.append(range_target_4)
    targets.append(range_target_5)
    # targets.append(range_target_6)
    # targets.append(wildcard_target)

    # results = []
    results = run_scan(targets)

    # # Test with sending directly with socket

    # packets = []
    # packets.append(_build_packet(known_open_local['host'], 51234, known_open_local['port']))
    # packets.append(_build_packet(known_closed_local['host'], 51234, known_closed_local['port']))

    # socket = conf.L3socket()
    # response, other = sndrcv(socket, packets[0])
    # socket.close()
    # log.info(response)
    # log.info(response[0][0])
    # log.info(other)
    # response = response[0][0]

    # tcp = response.getlayer(TCP)
    # flags = tcp.flags
    # flags_interpreted = [TCP_FLAGS_MAPPING[flag] for flag in flags]
    # log.info(flags_interpreted)

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Target
    parser.add_argument('--target', '-t')
    parser.add_argument('--port', '-p', help='Single port, range in start-end format, or * for all ports')
    # Scan behavior
    parser.add_argument('--threads', '-T', type=int, help='Number of threads to spawn for scanning')
    # Output
    parser.add_argument('--hide-closed', '-c', action='store_true', help='Hide closed targets in output')
    parser.add_argument('--debug', action='store_true', help='Set logging level to DEBUG')
    args = parser.parse_args()

    log.setLevel(logging.DEBUG) if args.debug else log.setLevel(logging.INFO)
    CONFIG['hide_closed'] = args.hide_closed
    CONFIG['thread_count'] = args.threads
    TEST_RUN = False if args.target or args.port else True

    log.info('Starting')

    if TEST_RUN:
        results = basic_test()
    else:
        targets = [{'host': args.target, 'port': args.port, 'protocol': 'tcp'}]
        log.debug(f"Running scan on {targets}")
        run_scan(targets)

    log.info('Complete')
