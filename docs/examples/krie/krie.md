# krie
[Linux Kernel Runtime Integrity with eBPF (krie)](https://github.com/gui774ume/krie)
is a very interesting research project by Guillaume Fournier.
The work contains original ideas on the problem of mitigating Linux
kernel exploits using BPF. For example, krie explores the possibilities
to use BPF to enforce CFI at certain points
in order to make it harder for kernel ROP chains to call
`prepare_kernel_creds` and `commit_creds`, which is commonly used in
attacks to give the exploiting process root privileges.
See his
[presentation](https://www.blackhat.com/us-22/briefings/schedule/index.html#return-to-sender---detecting-kernel-exploits-with-ebpf-27127)
for more information.

kire is a good example as it loads about 214 BPF programs (`lsm`: 148,
`tracepoint`: 10, `kprobe`: 46, `perf_event`: 2, `cgroup_sysctl`: 1)
and 31 maps ( 1 array, 9 hash, 5 lru_hash, 13 percpu_array,
1 perf_event_array, 2 prog_array).

To find out more about how krie works we can list all programs in the
dump and grep for the one we are interested in.
```
# vol -f /io/dumps/krie-3410c66d-26be0e1ef560.elf linux.bpf_listprogs | rg 'kprobe_commit_creds'
OFFSET (V)      ID      NAME    TYPE    LOADED AT       HELPERS MAPS    LINK TYPE       ATTACH TYPE     ATTACH TO
...
0xc90002afc000 279     kprobe_commit_creds  BpfProgType.BPF_PROG_TYPE_KPROBE        2023-03-09 14:01:10.990377      bpf_probe_read_kernel,bpf_get_current_comm,bpf_get_current_task,__htab_map_lookup_elem,bpf_get_smp_processor_id,bpf_perf_event_output,bpf_ktime_get_ns,bpf_probe_read_compat_str,percpu_array_map_lookup_elem,bpf_send_signal,bpf_get_current_pid_tgid        50,51,66,54     n.a.    kprobe/commit_creds
```
The plugin shows us some information like the address of the program
or the BPF helper functions it uses. For example, we can see that it
uses the `bpf_send_signal` helper, probably to kill the process
if an exploit is detected.

To get more details, we can use the same plugin to obtain the machine
code of the program. Here we can see that, indeed, signal number 9, i.e.,
SIGKILL, might be sent to the current process.
```
# cat /io/output/0xc90002afc000_prog_279_mdisasm | rg 'signal' -C2
 0xffffa0084285: 0f 84 46 c1 ff ff                            je 0xffffa00803d1
 0xffffa008428b: bf 09 00 00 00                               mov edi, 9
 0xffffa0084290: e8 ab 76 12 e1                               call 0xffff811ab940       # bpf_send_signal
 0xffffa0084295: e9 37 c1 ff ff                               jmp 0xffffa00803d1
```

Using the `bpf_listmaps` plugin, we can find out which maps the program
is using.
```
# vol -f /io/dumps/krie-3410c66d-26be0e1ef560.elf linux.bpf_listmaps --id 50 51 66 54
Volatility 3 Framework 2.4.2
Progress:  100.00               Stacking attempts finished
OFFSET (V)      ID      NAME    TYPE    KEY SIZE        VALUE SIZE      MAX ENTRIES

0x88800220ee00  50      process_context BpfMapType.BPF_MAP_TYPE_PERCPU_ARRAY    4       2040    2
0x888006023400  51      policies        BpfMapType.BPF_MAP_TYPE_HASH    4       4       14
0x88800220ea00  54      events  BpfMapType.BPF_MAP_TYPE_PERF_EVENT_ARRAY        4       4       4
0x888006986600  66      register_event_ BpfMapType.BPF_MAP_TYPE_PERCPU_ARRAY    4       2104    2
```
In a future version of the plugin we will also be able to inspect the
contents of those maps.



