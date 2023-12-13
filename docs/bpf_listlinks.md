# List Bpf Links

## User Documentation

The purpose of this plugin is to display a list of all BPF links in the memory image, i.e., to simulate the functionality of the `link` subcommand of `bpftool`.

For each BPF link it displays the following pieces of information:

- `OFFSET (V)`
- `ID`
- `TYPE`
- `PROG`: ID of the attached program
- `ATTACH`: extra information about the associated attachment point

## Developer Documentation

The plugin has the following public API
```python
@classmethod
def list_links(
    cls,
    context: ContextInterface,
    vmlinux_module_name: str = "kernel",
    filter_func: Callable[[BpfLink], bool] = lambda _: False,
) -> Iterable[BpfLink]:
```

## Technical Documentation

We iterate the `link_idr` and follow the stored pointers to the `bpf_link` structures. The link information is collected by studying the `bpf_link_get_info_by_id` function.
