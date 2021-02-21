#!/usr/bin/env python

import logging
import argparse
from scapy.all import sr1, IP, TCP
import time
import json
from tabulate import tabulate


FORMAT = "%(asctime)s : %(name)s : %(levelname)-8s : %(message)s"
logging.basicConfig(format=FORMAT)
# logging.getLogger('scapy').setLevel(logging.WARNING)
log = logging.getLogger('quickscan')


# Run test scan
TESTING = True
# TCP flag mappings
TCP_FLAGS = {
    'S': 'SYN',
    'A': 'ACK',
    'F': 'FIN',
    'R': 'RST',
    'P': 'PSH',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}


def _scan_target(host:str, port:int, protocol:str) -> dict:
    """
    Run scan on a particular combination
    """
    target = f"{host}:{port}/{protocol}"
    log.debug(f"Scanning {target}")

    # Do the scan
    # TODO: set a timeout to make sure it scans fast even if no response
    # TODO: randomized source port
    sport = 51234
    scan_response_packet = sr1(IP(dst=host) / TCP(sport=sport, dport=port, flags="S"), verbose=False)
    # tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
    # tcpResponse = sr1(tcpRequest,timeout=1,verbose=0)
    # log.debug(f"scan_response_packet: {scan_response_packet.summary()}")

    # Interpret results
    tcp = scan_response_packet.getlayer(TCP)
    flags = tcp.flags
    flags_interpreted = [TCP_FLAGS[flag] for flag in flags]
    log.debug(f"Flags: {flags_interpreted}")

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


def _build_scan_targets():
    """
    Given some information of hosts, ports, other information, turn that into a list we can use to run scans with

    TODO: interpret wildcars, port ranges, etc. into discrete targets
    """
    pass


def _submit_scan_job(targets:list):
    """
    Run a multithreaded scan across all targets specified
    """
    # TODO: non-multithreaded for now
    results = []
    for target in targets:
        host = target['host']
        port = target['port']
        protocol = target['protocol']
        result = _scan_target(host, port, protocol)
        # result = _interpret_packet(scan_packet)
        results.append(result)

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
    log.debug(f"Provided targets {len(targets)}")
    _build_scan_targets()
    log.debug(f"Built into {len(targets)} targets")

    log.info(f"Starting scan on {len(targets)} targets")
    start = time.time()
    results = _submit_scan_job(targets)
    end = time.time()

    elapsed = end - start
    log.info(f"Scan time: {elapsed:.5f} seconds")

    # TODO: replace with table format
    # print(json.dumps(results, indent=4))
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
        'port': 123,
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

    targets.append(known_open_local)
    targets.append(known_closed_local)
    targets.append(example_http)
    targets.append(example_https)
    targets.append(google_http)
    targets.append(google_https)

    results = run_scan(targets)

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='Set logging level to DEBUG')
    # parser.add_argument('--dry-run', '-n', action='store_true', help='Run without moving anything, just identify files')
    args = parser.parse_args()

    log.setLevel(logging.DEBUG) if args.debug else log.setLevel(logging.INFO)

    log.info('Starting')

    if TESTING:
        results = basic_test()
    else:
        # TODO: take in user input
        pass

    log.info('Complete')
