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
- variety of useful output formats for reports and interpreting for your own automation! (json, csv, markdown tables)

When scanning local hosts, bandwidth and resources are almost never a bottleneck and I want results now rather than waiting 10, 20, or more seconds to see what nmap finds. There are also a few quirks with nmap such as the output format. What quickscan does is make it fast and simple. Try it out!

Getting Started
---------------

- Setup

    ```bash
    git clone https://github.com/RaytingSec/quickscan.git
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
    python quickscan.py {parameters}
    ```

- Tests:

    ```bash
    pytest
    ```

Sample Output
-------------

```
| target                 | status   | open   | flags          |
|:-----------------------|:---------|:-------|:---------------|
| 10.1.0.1:22/tcp        | open     | True   | ['SYN', 'ACK'] |
| 10.1.0.1:123/tcp       | closed   | False  | ['RST', 'ACK'] |
| 93.184.216.34:80/tcp   | open     | True   | ['SYN', 'ACK'] |
| 93.184.216.34:443/tcp  | open     | True   | ['SYN', 'ACK'] |
| 142.250.72.206:80/tcp  | open     | True   | ['SYN', 'ACK'] |
| 142.250.72.206:443/tcp | open     | True   | ['SYN', 'ACK'] |
```

| target                 | status   | open   | flags          |
|:-----------------------|:---------|:-------|:---------------|
| 10.1.0.1:22/tcp        | open     | True   | ['SYN', 'ACK'] |
| 10.1.0.1:123/tcp       | closed   | False  | ['RST', 'ACK'] |
| 93.184.216.34:80/tcp   | open     | True   | ['SYN', 'ACK'] |
| 93.184.216.34:443/tcp  | open     | True   | ['SYN', 'ACK'] |
| 142.250.72.206:80/tcp  | open     | True   | ['SYN', 'ACK'] |
| 142.250.72.206:443/tcp | open     | True   | ['SYN', 'ACK'] |

Outstanding Items
-----------------

Todo

- [ ] multithreaded scanning
- [ ] take in complex scan inputs for IP and ports, like CIDRs, wildcards, and ranges
- [ ] smarter detection of open/close
- [ ] detailed reports of scan results, to terminal and to file
- [ ] different scan types from SYN scans, i.e. RST, UDP, etc.
- [ ] input json/csv file with target list

Additional features

- [ ] specify source port for scans
- [ ] `setup.py` for building into a python package
