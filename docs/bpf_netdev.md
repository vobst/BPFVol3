# Discover Traffic Control Programs

## User Documentation

The aim of this plugin is to list tc BPF programs attached to network interfaces.

For each network interface the plugin displays the following pieces of information:

- `NAME`: name of the network interface
- `MAC ADDR`
- `EGRESS`: comma-separated list of IDs of BPF programs processing outgoing packets
- `INGRESS`: comma-separated list if IDs of BPF program processing incoming packets

## Developer Documentation

The plugin has the following public API:
```python
@classmethod
def list_bpf_cls(
    cls,
    context: ContextInterface,
    vmlinux_module_name: str,
) -> Iterable[
    tuple[ObjectInterface, net_device, list[BpfProg], list[BpfProg]]
]:
```
Here the first member of the returned tuple is the network namespace of the network device.

## Technical Documentation

The plugin relies on the [`mini_Qdisc`](https://elixir.bootlin.com/linux/v6.1.65/source/include/net/sch_generic.h#L1265) structure that is used on the transmission and receive fast paths to look up queuing disciplines (qdisc) attached to a network device.

We use the [`ifconfig plugin`](https://github.com/volatilityfoundation/community3/blob/master/Sheffer_Shaked_Docker/plugins/ifconfig.py) by Ofek Shaked and Amir Sheffer to obtain a list of all network devices. Then, we find the above-mentioned structure and use it to collect all BPF programs that are involved into qdiscs on this device. With kernel 6.3 the process of locating the `mini_Qdisc` from the network interface changed slightly due to the introduction of link-based attachment of tc programs, however, the plugin recognizes and handles both cases.
