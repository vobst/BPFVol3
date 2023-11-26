# List Processes that use BPF

## User Documentation

The purpose of this plugin is to display a list of processes that
hold BPF objects via an fd.

For each process that holds at least one BPF object it displays the
following pieces of information:

- PID
- COMM
- PROGS: comma separated list of IDs of BPF programs that the process
has an fd for
- MAPS: comma separated list of IDs of BPF maps that the process
has an fd for
- LINKS: comma separated list of IDs of BPF links that the process
has an fd for

## Technical Documentation

Here we just call Volatility's `Lsof` plugin and filter out the
intersting files using their file operations pointer. The BPF objects
are always stored in the private data.
