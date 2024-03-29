# List BPF maps

## User Documentation

The purpose of this plugin is to display a list of BPF maps that are currently loaded into the kernel, i.e., to simulate the `map` subcommand of `bpftool`.

For each map it displays the following pieces of information:

- `OFFSET`: kernel virtual address where the `bpf_map` structure is located
- `ID`: unique ID of the map
- `TYPE`: [map type](https://docs.kernel.org/bpf/maps.html#:~:text=BPF%20'maps'%20provide%20generic%20storage,based%20on%20the%20map%20contents.)
- `NAME`: name string that was supplied when loading the map
- `KEY SIZE`: size of the type that is used to index into the map (in bytes)
- `VALUE SIZE`: size of the type that is stored in the map (in bytes)
- `MAX ENTRIES`: maximal number of entries that the map can hold

The understood command line parameters are:

- `--id`: list of space-separated IDs to filter the output
- `--dump`: writes the contents of the map(s) to a text file, uses BTF for pretty printing, defaults to hexdump if no BTF is available

## Developer Documentation

The plugin has the following public API:
```python
@classmethod
def list_maps(
    cls,
    context: ContextInterface,
    vmlinux_module_name: str = "kernel",
    filter_func: Callable[[BpfMap], bool] = lambda _: False,
) -> Iterable[BpfMap]:
```

## Technical Documentation

For a general description of the process used to generate the list we refer the reader to the documentation of the `bpf_listprogs` plugin or our [blog post]() about the plugins.

All of the displayed information can be found in the `bpf_map` object we reach via the `map_idr`. The collection of general information about the map is modeled after the `bpf_map_get_info_by_id` function.

Retrieving the map contents requires a bit of map type dependent logic. The only novelty here is the usage of [BTF](https://docs.kernel.org/bpf/btf.html) to pretty-print the raw bytes stored in a map. In a nutshell, BTF is a format to store C type information - think DWARF, just a lot smaller and simpler. As BTF is tightly integrated into the BPF ecosystem, there is at least a chance we might find it during an investigation. The implementation is inspired by the [`bpf_snprintf_btf`](https://elixir.bootlin.com/linux/v6.2.4/source/kernel/trace/bpf_trace.c#L999) BPF helper function.
