# Discover Hidden BPF LSM Programs

## User Documentation

The plugin aims to discover hidden BPF programs attached to LSM hooks.

For each LSM-hook with attached BPF programs it displays the following pieces of information:

- `LSM HOOK`: name of the hook
- `Nr. PROGS`: number of BPF programs attached to the hook
- `IDS`: comma-separated list of IDs of the programs attached to the hook

For each hook with hidden programs a warning is printed to the console.

## Developer Documentation

The plugin has the following public API:
```python
@classmethod
def list_bpf_lsm(
    cls,
    context: ContextInterface,
    symbol_table: str,
) -> Iterable[tuple[SymbolInterface, list[BpfProg]]]:
"""Generates all the LSM hooks that have at least one BPF
program attached"""
```

## Technical Documentation

See our detailed [blog post](https://blog.eb9f.de/2023/04/24/lsm2bpf.html) on this plugin.
