# List BPF programs
## User Documentation
The purpose of this plugin is to display a list of BPF programs that
are currently loaded into the kernel.

For each program it displays the following pieces of information:
- OFFSET: kernel virtual address where the `bpf_proc` structure
is located
- ID: unique ID of the program
- NAME: name string that was supplied when loading the program
- TYPE: program type
- LOADED AT: ns since boot when program was loaded
- HELPERS: list of all
[BPF helper functions](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html)
that might be used by the program
- MAPS: list of all BPF maps that might be used by the program
- LINK TYPE: if the program is referenced by a BPF link, the link type
- ATTACH TYPE: if the program is attached, the attach type
- ATTACH TO: if the program is attached, the event (uses the
[ELF section format of libbpf](https://libbpf.readthedocs.io/en/latest/program_types.html)
,when possible)

The understood command line parameters are:
- `--id`: list of space-separated IDs to filter the output
- `--dump-xlated`: write the bytecode representation of the program to
a text file
- `--dump-jited`: write the machine code representation of the program
to a text file

## Technical Documentation
On load, each BPF object is assigned an ID, which is unique per object
type and system restart. Internallly, the BPF subsystem uses the
[IDR kernel API](https://www.kernel.org/doc/html/latest/core-api/idr.html)
to allocate those IDs. For that purpose, it declares global variables
```C
// /kernel/bpf/syscall.c
static DEFINE_IDR(prog_idr);
static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(map_idr);
static DEFINE_SPINLOCK(map_idr_lock);
static DEFINE_IDR(link_idr);
static DEFINE_SPINLOCK(link_idr_lock);
```
To realize the ID allocation, the IDR subsystem uses the kernel's
radix tree data structure, which is really just an
[XArray](https://www.kernel.org/doc/html/latest/core-api/xarray.html).
The ID is an index into the array, and the corresponding slot stores a
pointer to the data structure that represents the object.
In the plugin, we iterate over the `prog_idr` array to list all programs
that are currently loaded.

Almost all of the information that is displayed by the plugin can be
obtained from the `bpf_prog` data structure that was found in the array.
However, to display the attachment point of a program that is both
loaded and attached we need more information.

There are many ways by which a loaded program might come into execution,
and to find its attachment point(s) we potentially have to check
multiple of them separately. (Possible attachment mechanisms are
limited by the program type and expected attach type, which can be
found in the `bpf_prog` structure.)

The most straightforward way to find an attachment point is by looking
at BPF links. Therefore, we start by iterating the `link_idr`,
looking for links that reference the program. From there, we can use
link type dependent logic to find the attachment point.
Since the BPF link abstraction was only introduced in 2020, it coexists
with more specific attachment mechanisms:

- To find programs that are attached to network interfaces, we can
iterate over the list of `net_device` objects and check their queuing
disciplines.

Unfortunately, there are many more ways by which a BPF program might be
attached, and we currently do not cover all of them.
