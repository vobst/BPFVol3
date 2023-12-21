# krie

- Image: [3a3549ff75bafbf103edf0ca3a5cdb39.7z](https://owncloud.fraunhofer.de/index.php/s/i88sl3p69HbxpAC)
- Symbols: [38af54e756b759b46c7e6810b98a6bdf.7z](https://owncloud.fraunhofer.de/index.php/s/lRtAXFOO1KMsiuH)

[Linux Kernel Runtime Integrity with eBPF (krie)](https://github.com/gui774ume/krie) is an interesting research project by Guillaume Fournier that addresses the problem of defending against Linux kernel exploits using BPF. For example, krie uses BPF programs to enforce control flow integrity at certain functions that are commonly called in kernel ROP chains, e.g., `prepare_kernel_creds` and `commit_creds`. See the [BlackHat 2022 presentation](https://www.blackhat.com/us-22/briefings/schedule/index.html#return-to-sender---detecting-kernel-exploits-with-ebpf-27127) for more information.

`krie` is a good example as it loads about 214 BPF programs (`lsm`: 148, `tracepoint`: 10, `kprobe`: 46, `perf_event`: 2, `cgroup_sysctl`: 1) and 31 maps ( 1 `array`, 9 `hash`, 5 `lru_hash`, 13 `percpu_array`, 1 `perf_event_array`, 2 `prog_array`).

To get started, we can list all the programs that were loaded when the image was acquired.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listprog
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
OFFSET (V)      ID      TYPE    NAME    TAG     LOADED AT       MAP IDs BTF ID  HELPERS

0xc9000004d000  2       TRACING dump_bpf_map    5ab0aca540a5c85c        1961266639      2       2       bpf_seq_printf
0xc90000065000  3       TRACING dump_bpf_prog   43667a516246cff7        1978569229      2       2       bpf_probe_read_kernel,bpf_seq_printf
0xc90000085000  6       CGROUP_DEVICE   sd_devices      457dd60b5425d2d5        7299940339              -1
0xc9000009d000  7       CGROUP_SKB      sd_fw_egress    6deef7357e7b4530        7310864779              -1
0xc900000b5000  8       CGROUP_SKB      sd_fw_ingress   6deef7357e7b4530        7313761329              -1
0xc90000179000  9       CGROUP_SKB      sd_fw_egress    6deef7357e7b4530        8407770059              -1
0xc90000191000  10      CGROUP_SKB      sd_fw_ingress   6deef7357e7b4530        8408473209              -1
0xc9000003f000  221     LSM     lsm_security_shm_associate      55aa65e5a731c3a2        1416263925509   50,40,45        8       bpf_probe_read_kernel,percpu_array_map_lookup_elem,bpf_probe_read_compat_str,bpf_get_current_comm,bpf_get_current_task,__htab_map_lookup_elem,bpf_send_signal,bpf_get_current_pid_tgid
0xc9000032f000  222     KPROBE  kprobe__32_sys_init_module      33a82d1f2b351bc9        1417276884529   37,61,38,40,45,51,54    8       bpf_override_return,bpf_probe_read_kernel,percpu_array_map_lookup_elem,htab_lru_map_delete_elem,htab_map_update_elem,bpf_probe_read_compat_str,bpf_ktime_get_ns,bpf_get_current_comm,bpf_get_current_task,bpf_get_smp_processor_id,__htab_map_lookup_elem,bpf_send_signal,bpf_get_current_pid_tgid,bpf_perf_event_output,htab_lru_map_update_elem
[...]
0xc90003850000  426     LSM     lsm_security_sb_clone_mnt_opts  55aa65e5a731c3a2        1519727340229   50,40,45        8       bpf_probe_read_kernel,percpu_array_map_lookup_elem,bpf_probe_read_compat_str,bpf_get_current_comm,bpf_get_current_task,__htab_map_lookup_elem,bpf_send_signal,bpf_get_current_pid_tgid
0xc900038d2000  427     LSM     lsm_security_inode_setxattr     55aa65e5a731c3a2        1520153714369   50,40,45        8       bpf_probe_read_kernel,percpu_array_map_lookup_elem,bpf_probe_read_compat_str,bpf_get_current_comm,bpf_get_current_task,__htab_map_lookup_elem,bpf_send_signal,bpf_get_current_pid_tgid
```

Let's find out more about the CFI enforcement mechanism we discussed above. To start, we can restrict the output to the program we are interested in.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listprog --id 279
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
OFFSET (V)      ID      TYPE    NAME    TAG     LOADED AT       MAP IDs BTF ID  HELPERS

0xc90002afc000  279     KPROBE  kprobe_commit_creds     7ea8afb77553ae92        1445995582319   50,51,66,54     8       bpf_perf_event_output,bpf_get_smp_processor_id,bpf_probe_read_kernel,bpf_send_signal,bpf_get_current_pid_tgid,bpf_get_current_comm,bpf_probe_read_compat_str,bpf_get_current_task,bpf_ktime_get_ns,__htab_map_lookup_elem,percpu_array_map_lookup_elem
```

As we can see, the program might use the `bpf_send_signal` helper to send a signal to the current task. Which signal might it be? Let's disassemble the program to find out.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listprog --id 279 --dump-jited
[...]
# cat .prog_0xc90002afc000_279_mdisasm | grep send_signal -B 10
 0xffffa0084261: 0f 87 6a c1 ff ff                            ja 0xffffa00803d1 # kprobe_commit_creds + 0x65
 0xffffa0084267: be 01 04 00 00                               mov esi, 0x401
 0xffffa008426c: 48 c1 e6 20                                  shl rsi, 0x20
 0xffffa0084270: 48 c1 ee 20                                  shr rsi, 0x20
 0xffffa0084274: 48 39 f7                                     cmp rdi, rsi
 0xffffa0084277: 0f 84 54 c1 ff ff                            je 0xffffa00803d1 # kprobe_commit_creds + 0x65
 0xffffa008427d: bf 01 00 00 00                               mov edi, 1
 0xffffa0084282: 48 85 ff                                     test rdi, rdi
 0xffffa0084285: 0f 84 46 c1 ff ff                            je 0xffffa00803d1 # kprobe_commit_creds + 0x65
 0xffffa008428b: bf 09 00 00 00                               mov edi, 9
 0xffffa0084290: e8 ab 76 12 e1                               call 0xffff811ab940       # bpf_send_signal
```
It send signal no. 9, i.e., `SIGKILL`, probably in an attempt to stop the task from executing after elevating its privileges.

Looking at the map names gives us a glimpse of the complex state machine formed by the more than two hundred programs.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listmaps
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
OFFSET (V)      ID      TYPE    NAME    KEY SIZE        VALUE SIZE      MAX ENTRIES

0xc90000045ef0  2       ARRAY   iterator.rodata 4       98      1
0x888006022400  37      LRU_HASH        syscalls        8       72      1024
0x88800220f800  38      PERCPU_ARRAY    event_check_eve 4       2080    2
0x888006022000  39      LRU_HASH        bpf_progs       4       64      4096
[...]
0x88800220e200  60      PERCPU_ARRAY    bpf_filter_even 4       2088    2
0x88800220e000  61      PERCPU_ARRAY    init_module_eve 4       2136    2
0x888006986000  62      PERCPU_ARRAY    ptrace_event_ge 4       2088    2
0x88800699bc00  63      HASH    sysctl_paramete 256     264     1024
0x888006986200  64      PERCPU_ARRAY    syscall_table_e 4       2096    2
0x88800699ac00  65      HASH    kernel_paramete 4       32      25
0x888006986600  66      PERCPU_ARRAY    register_event_ 4       2104    2
```

By looking at the links we notice that only the LSM programs were attached using this mechanism. The other program types use legacy attachment mechanisms without links.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listlinks
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
OFFSET (V)      ID      TYPE    PROG    ATTACH

0x8880059fc0c0  1       ITER    2       target_name='bpf_map'
0x8880059fc120  2       ITER    3       target_name='bpf_prog'
0x888008670700  151     TRACING 346     attach_type='LSM_MAC';obj_id=1;btf_id=28127
0x888008670480  152     TRACING 364     attach_type='LSM_MAC';obj_id=1;btf_id=28129
0x888008670580  153     TRACING 307     attach_type='LSM_MAC';obj_id=1;btf_id=28130
0x888008670500  154     TRACING 350     attach_type='LSM_MAC';obj_id=1;btf_id=28132
0x888008670400  155     TRACING 357     attach_type='LSM_MAC';obj_id=1;btf_id=28134
[...]
0x8880130bd680  296     TRACING 422     attach_type='LSM_MAC';obj_id=1;btf_id=28445
0x8880130bd600  297     TRACING 352     attach_type='LSM_MAC';obj_id=1;btf_id=28447
0x8880130bd580  298     TRACING 296     attach_type='LSM_MAC';obj_id=1;btf_id=28449
```

An overview of the processes that hold BPF resources can be obtained using the `bpf_listproc` plugin. Unsurprisingly, the `krie` user-space process is the number one.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_listprocs
Volatility 3 Framework 2.5.2
Progress:  100.00               Stacking attempts finished
PID     COMM    PROGS   MAPS    LINKS

1       systemd 6,7,8,9,10
1025    krie    221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,271,272,273,274,275,276,277,278,279,280,281,282,283,284,285,286,287,288,289,290,291,292,293,294,295,296,297,298,299,300,301,302,303,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339,340,341,342,343,344,345,346,347,348,349,350,351,352,353,354,355,356,357,358,359,360,361,362,363,364,365,366,367,368,369,370,371,372,373,374,375,376,377,378,379,380,381,382,383,384,385,386,387,388,389,390,391,392,393,394,395,396,397,398,399,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,427        37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,54    151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,271,272,273,274,275,276,277,278,279,280,281,282,283,284,285,286,287,288,289,290,291,292,293,294,295,296,297,298
```

What do you think: is `krie` hiding some of its LSM hooks to protect them from being disabled by exploits? The `bpf_lsm` plugin has the unsurprising answer: all hooks are connected to links that are present in the above list.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_lsm
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
LSM HOOK        Nr. PROGS       IDs

bpf_lsm_binder_set_context_mgr  1       346
bpf_lsm_binder_transaction      1       364
bpf_lsm_binder_transfer_binder  1       307
[...]
bpf_lsm_tun_dev_alloc_security  1       308
bpf_lsm_tun_dev_attach  1       399
bpf_lsm_tun_dev_attach_queue    1       389
bpf_lsm_tun_dev_create  1       270
bpf_lsm_tun_dev_open    1       422
bpf_lsm_unix_may_send   1       297
bpf_lsm_unix_stream_connect     1       286
```

Just to be sure, let's quickly check that there are no hidden networking programs.
```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_netdev
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
NAME    MAC ADDR        EGRESS  INGRESS
```

Ok, there are not. Finally, we can use the `bpf_graph` plugin to get a visual representation all the programs, maps, links and processes. Programs are connected to the maps and links they use. Processes are connected to the BPF resources they hold via fd. Coloring of BPF objects is based on their load type while processes are colored based on their pid. I must admit, it is a bit overwhelming, but I promise we are planning to make the graph more useful in the future - adding a legend would be a good first step ;)

![krie-3410c66d-26be0e1ef560.elf.png](https://blog.eb9f.de/media/bpf_memory_forensics_with_volatility_3/krie-3410c66d-26be0e1ef560.elf.png)

However, there is something that we can do to reduce the complexity at least somewhat. First, the plugin accepts a list of node types that should be included in the output. Second, we can specify a list of nodes and only the connected components that include at least one of them will be included in the output. Invoking the plugin like that produces a somewhat less messy graph.

```console
# vol -f /io/dumps/3a3549ff75bafbf103edf0ca3a5cdb39.elf linux.bpf_graph --components prog-279 --types prog map
Volatility 3 Framework 2.5.0
Progress:  100.00               Stacking attempts finished
STATUS  FILE

OK      graph.dot
OK      graph.png
```

![krie-3410c66d-26be0e1ef560_filtered.png](https://blog.eb9f.de/media/bpf_memory_forensics_with_volatility_3/krie-3410c66d-26be0e1ef560_filtered.png)
