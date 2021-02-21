import quickscan


# Sample targets
known_open_local = {  # Local router
    'host': '10.1.0.1',
    'port': 22,
    'protocol': 'tcp'
}
known_open_remote = {  # example.com
    'host': '93.184.216.34',
    'port': 80,
    'protocol': 'tcp'
}
known_closed_local = {  # Local router
    'host': '10.1.0.1',
    'port': 12345,
    'protocol': 'tcp'
}


def test_open_port():
    """
    Verify scan of an open target
    """
    results = quickscan._scan_target(**known_open_local)

    assert results['status'] == 'open'
    assert results['open']


def test_closed_port():
    """
    Verify scan of a closed target
    """
    results = quickscan._scan_target(**known_closed_local)

    assert results['status'] == 'closed'
    assert not results['open']


def test_scan_results():
    """
    Verify run_scan works and results are expected
    """
    targets = [
        known_open_local,
        known_open_remote,
        known_closed_local
    ]

    results = quickscan.run_scan(targets)

    assert results[0]['status'] == 'open'
    assert results[0]['open']
    assert results[1]['status'] == 'open'
    assert results[1]['open']
    assert results[2]['status'] == 'closed'
    assert not results[2]['open']
