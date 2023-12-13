# List BPF programs

## User Documentation

The purpose of this plugin is to display a list of BPF programs that are currently loaded into the kernel, i.e., to simulate the `prog` subcommand of `bpftool`.

For each program it displays the following pieces of information:

- `OFFSET (V)`: kernel virtual address where the `bpf_proc` structure is located
- `ID`: unique ID of the program
- `TYPE`: program load type
- `NAME`: name string that was supplied when loading the program
- `TAG`: sha1 hash over the program code
- `LOADED AT`: ns since boot when program was loaded
- `MAP IDs`: list of all BPF maps that might be used by the program
- `BTF IDs`: identifier of the BTF object describing the program
- `HELPERS`: list of all [BPF helper functions](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html) that might be used by the program

The understood command line parameters are:

- `--id`: list of space-separated IDs to filter the output
- `--dump-xlated`: write the bytecode representation of the program(s) to a text file
- `--dump-jited`: write the machine code representation of the program(s) to a text file
- `--raw` can be combined with the dumping options to write the bytes instead of the disassembly

## Developer Documentation

The plugin has the follow public API:
```python
@classmethod
def list_progs(
    cls,
    context: ContextInterface,
    vmlinux_module_name: str = "kernel",
    filter_func: Callable[[BpfProg], bool] = lambda _: False,
) -> Iterable[BpfProg]:
```

## Technical Documentation

On load, each BPF object is assigned an ID, which is unique per object type and system restart. Internally, the BPF subsystem uses the [IDR kernel API](https://www.kernel.org/doc/html/latest/core-api/idr.html) to allocate those IDs. For that purpose, it declares global variables

```C
// /kernel/bpf/syscall.c
static DEFINE_IDR(prog_idr);
static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(map_idr);
static DEFINE_SPINLOCK(map_idr_lock);
static DEFINE_IDR(link_idr);
static DEFINE_SPINLOCK(link_idr_lock);
```

To realize the ID allocation, the IDR subsystem uses the kernel's radix tree data structure, which is really just an [XArray](https://www.kernel.org/doc/html/latest/core-api/xarray.html). The ID is an index into the array, and the corresponding slot stores a pointer to the data structure that represents the object. In the plugin, we iterate over the `prog_idr` array to list all programs that are currently loaded.

Almost all of the information that is displayed by the plugin can be obtained from the `bpf_prog` data structure that was found in the array. In particular, we model the `bpf_prog_get_info_by_fd` function.

The bytecode is stored in the `insni` flexible array member of the `bpf_prog` structure while the machine code is pointed to by the `bpf_func` member. We describe the process of symbolizing the disassembly in more detail in the [blog post]().
