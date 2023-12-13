# List Processes that use BPF

## User Documentation

The purpose of this plugin is to display a list of processes that hold BPF objects via an fd.

For each process that holds at least one BPF object it displays the following pieces of information:

- `PID`
- `COMM`
- `PROGS`: comma separated list of IDs of BPF programs that the process has an fd for
- `MAPS`: comma separated list of IDs of BPF maps that the process has an fd for
- `LINKS`: comma separated list of IDs of BPF links that the process has an fd for

## Developer Documentation

The plugin has the following public API
```python
@classmethod
def list_bpf_procs(
    cls,
    context: ContextInterface,
    symbol_table: str,
) -> Iterable[
    tuple[task_struct, list[BpfProg], list[BpfMap], list[BpfLink]]
]:
```

## Technical Documentation

We call Volatility's `Lsof.list_fds` plugin to get a list of all file desciptors of all processes. We then filter for files corresponding to BPF objects using the file operations `f_op` pointer. The pointer to the BPF objects are always stored in the `private_data` member of the file struct.
