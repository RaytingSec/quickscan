quickscan
====================

Primer
----------

### What is this

Port scan against one or more hosts, attempting to get results in a reasonably fast manner. The intent is it could be used against local hosts. It could be just after deployment to see what ports have been opened, or an old host where the exact services and open ports are unknown. It takes no precautions against rate limiting, IDS/IPS, and is not made to be sneaky.

### But why not nmap

nmap is known, familiar, and reasonably fast.

But with quickscan:

- Made to run scans very fast! Especially useful in local environments where noise is not a concern (if you're trying to be covert, you really shouldn't be active scanning in the first place)
- Variety of output formats useful for reports and interpreting for your own automation! (json, csv, markdown tables)

When scanning local hosts, bandwidth and resources are almost never a bottleneck and I want results now rather than waiting 10, 20, or more seconds to see what nmap finds. There are also a few quirks with nmap such as the output format. What quickscan does is make it fast and simple. Try it out!

For a comparison of performance, see respective section below.

Getting Started
---------------

- Setup

    ```bash
    git clone https://github.com/RaytingSec/quickscan.git
    cd quickscan
    virtualenv .venv
    pip install -r requirements
    ```

    Scans are run with scapy which need root permissions. Alternatively, enable capability to send raw packets:

    ```bash
    sudo setcap cap_net_raw=+eip /usr/bin/python3.8

    sudo getcap /usr/bin/python3.8  # Show changes

    sudo setcap cap_net_raw=-eip /usr/bin/python3.8  # Remove changes
    sudo setcap -r /usr/bin/python3.8  # Alternatively, reset completely
    ```

- Running:

    ```bash
    python src/quickscan.py {parameters}
    ```

- Tests:

    ```bash
    pytest
    ```

Sample Output
-------------

Scan targeting 10.1.0.1 on port 20-25:

```
2021-02-21 03:40:31,092 : quickscan : INFO     : Starting
2021-02-21 03:40:31,092 : quickscan : DEBUG    : Provided 1 targets: [{'host': '10.1.0.1', 'port': '20-25', 'protocol': 'tcp'}]
2021-02-21 03:40:31,092 : quickscan : DEBUG    : Built into 6
2021-02-21 03:40:31,092 : quickscan : INFO     : Starting scan on 6 targets
2021-02-21 03:40:31,096 : quickscan : DEBUG    : Scanning 10.1.0.1:21/tcp
2021-02-21 03:40:31,096 : quickscan : DEBUG    : Scanning 10.1.0.1:20/tcp
2021-02-21 03:40:31,096 : quickscan : DEBUG    : Scanning 10.1.0.1:22/tcp
2021-02-21 03:40:31,096 : quickscan : DEBUG    : Scanning 10.1.0.1:24/tcp
2021-02-21 03:40:31,096 : quickscan : DEBUG    : Scanning 10.1.0.1:25/tcp
2021-02-21 03:40:31,097 : quickscan : DEBUG    : Scanning 10.1.0.1:23/tcp
2021-02-21 03:40:31,097 : quickscan : INFO     : Open port found: 10.1.0.1:22/tcp
2021-02-21 03:40:31,098 : quickscan : INFO     : Scan time: 0.00571 seconds
| target          | status   | open   | flags   |
|:----------------|:---------|:-------|:--------|
| 10.1.0.1:20/tcp | closed   | False  | na      |
| 10.1.0.1:21/tcp | closed   | False  | na      |
| 10.1.0.1:22/tcp | open     | True   | na      |
| 10.1.0.1:23/tcp | closed   | False  | na      |
| 10.1.0.1:24/tcp | closed   | False  | na      |
| 10.1.0.1:25/tcp | closed   | False  | na      |
2021-02-21 03:40:31,099 : quickscan : INFO     : 1 targets open
2021-02-21 03:40:31,099 : quickscan : INFO     : Complete
```

Note that with scapy removed due to performance reasons, TCP response flags are not available.


Performance
-----------

- When scanning single host for all ports, this tool is slightly slower than nmap.

    + nmap

        ```
        real    0m3.660s
        user    0m0.661s
        sys     0m2.608s
        ```

    + quickscan

        ```
        real    0m5.831s
        user    0m4.143s
        sys     0m4.283s
        ```

    + old quickscan with scapy, saved for reference

        ```
        real    4m21.175s
        user    3m21.011s
        sys     0m33.817s
        ```

- Results start to get interesting when scanning across multiple hosts. Scanning three hosts for first 10,000 ports:

    + nmap

        ```
        real    0m13.885s
        user    0m0.655s
        sys     0m2.109s
        ```

    + quickscan


        ```
        real    0m12.532s
        user    0m5.432s
        sys     0m5.850s
        ```


Outstanding Items
-----------------

Todo

- [X] multithreaded scanning
- [ ] take in complex scan inputs for IP and ports, like CIDRs, wildcards, and ranges
- [ ] smarter detection of open/close
- [ ] detailed reports of scan results, to terminal and to file
- [ ] different scan types from SYN scans, i.e. RST, UDP, etc.
- [ ] input json/csv file with target list

Additional features

- [ ] specify source port for scans
- [ ] `setup.py` for building into a python package
