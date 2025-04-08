# inspector-core-library
Library for core functionalities of IoT Inspector

## Installation

To install the `libinspector` module via `pip` from GitHub, use the following command:

```sh
pip install git+https://github.com/nyu-mlab/inspector-core-library.git
```


## Usage

### Running the Inspector

To run the Inspector, you need to activate the virtual environment first and then run the following command:

```sh
sudo $(which python) -m libinspector.core
```

If you're debugging, you can run the following to reset the database and start the Inspector:

```sh
sudo truncate -s 0 inspector.log; sudo rm -f debug_mem_db.db; sudo $(which $(which python)) -m libinspector.core
```

By default, the traffic is saved in an in-memory SQLite database, so you won't see the data directly. Also, none of the devices are inspected by default. For debugging purposes, you can have `libinspector` dump the internal SQLite database to disk and inspect (i.e., ARP-spoof) traffic for ALL devices by doing the following:

1. Create a file `libinspector_config.json` in the same directory where you run `sudo python -m libinspector.core` (or where you import `libinspector` as a part of your package).

2. Edit this json file to include the following text:
```json
  {
      "use_in_memory_db": false,
      "inspect_every_device_by_default": true
  }
```

3. Remove the `libinspector_config.json` config file, or flip the above values in production.


### Embedding in Your Own Python Application

The preferred way to use `libinspector` is to embed it within your own Python application. You can do this by importing `libinspector.core` and calling the `start_threads()` method, which returns almost instantaneously. Your Python script will then need to read the in-memory SQLite database for information about the devices and the network traffic flows.

```python
import libinspector.core
import libinspector.global_state

# This method returns almost instantaneously
libinspector.core.start_threads()

# Make sure to sleep and/or do other work here, such as analyzing the in-memory SQLite database. For example, you can keep printing the device list from the `devices` table.
db_conn, rwlock = libinspector.global_state.db_conn_and_lock

while True:
    with rwlock:
        for device in db_conn.execute('SELECT mac_address, ip_address FROM devices').fetchall():
            print(f'MAC: {device["mac_address"]}, IP: {device["ip_address"]}')
    time.sleep(5)

```

### Data Schema

The data schema is defined in `mem_db.py` and includes the following tables:

- `devices`: Stores information about devices on the network.
  - `mac_address` (TEXT, PRIMARY KEY): The MAC address of the device.
  - `ip_address` (TEXT, NOT NULL): The IP address assigned to the device.
  - `is_inspected` (INTEGER, DEFAULT 0): Indicates whether the device is being inspected (1) or not (0).
  - `is_gateway` (INTEGER, DEFAULT 0): Indicates whether the device is a gateway (1) or not (0).
  - `updated_ts` (INTEGER, DEFAULT 0): The timestamp of the last update.
  - `metadata_json` (TEXT, DEFAULT '{}'): Additional metadata in JSON format.

- `hostnames`: Stores hostnames associated with IP addresses.
  - `ip_address` (TEXT, PRIMARY KEY): The IP address associated with the hostname.
  - `hostname` (TEXT, NOT NULL): The hostname of the device.
  - `updated_ts` (INTEGER, DEFAULT 0): The timestamp of the last update.
  - `data_source` (TEXT, NOT NULL): The source of the hostname data.
  - `metadata_json` (TEXT, DEFAULT '{}'): Additional metadata in JSON format.

- `network_flows`: Stores information about network flows.
  - `timestamp` (INTEGER): The timestamp of the network flow.
  - `src_ip_address` (TEXT): The source IP address of the flow.
  - `dest_ip_address` (TEXT): The destination IP address of the flow.
  - `src_hostname` (TEXT): The source hostname of the flow.
  - `dest_hostname` (TEXT): The destination hostname of the flow.
  - `src_mac_address` (TEXT): The source MAC address of the flow.
  - `dest_mac_address` (TEXT): The destination MAC address of the flow.
  - `src_port` (TEXT): The source port of the flow.
  - `dest_port` (TEXT): The destination port of the flow.
  - `protocol` (TEXT): The protocol used in the flow.
  - `byte_count` (INTEGER, DEFAULT 0): The number of bytes transferred in the flow.
  - `packet_count` (INTEGER, DEFAULT 0): The number of packets transferred in the flow.
  - `metadata_json` (TEXT, DEFAULT '{}'): Additional metadata in JSON format.
  - PRIMARY KEY (`timestamp`, `src_mac_address`, `dest_mac_address`, `src_ip_address`, `dest_ip_address`, `src_port`, `dest_port`, `protocol`): The composite primary key for the table.

### How `libinspector` Works

The `libinspector` module works by starting various threads to monitor and inspect network traffic. Here is a high-level overview of the `start_threads` function in `core.py`:

1. **Ensure Single Instance**: The function first ensures that only one instance of the Inspector core is running.
2. **Initialize Database**: It initializes the database by calling `mem_db.initialize_db()`.
3. **Initialize Networking Variables**: It enables IP forwarding and updates the network information.
4. **Start Threads**: It starts several threads to perform various tasks:
   - Update network info from the OS every 60 seconds.
   - Discover devices on the network every 10 seconds.
   - Collect and process packets from the network.
   - Spoof internet traffic.
   - Start the mDNS and UPnP scanner threads.


## Notes

TODO:
 - Publish to PyPI.


## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

Ask Prof. Danny Y. Huang (dhuang@nyu.edu).

