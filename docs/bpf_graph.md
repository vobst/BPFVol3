# Visualize the state of BPF

## User Documentation

The purpose of this plugin is to display the combined analysis results in a human-friendly way. We intend this to be a quick way to get a high-level overview of the state of the BPF subsystem.

Nodes are either:

- processes that hold BPF some resource (diamond shape)
- maps (oval shape)
- programs (note shape)
- links (hexagon shape)

Edges are either indicating that a:

- program uses a map (solid line)
- process holds an fd for a BPF object (dotted line)
- link refers to a program (dashed line)

Node labels and properties provide more information on the object they represent, e.g., the ID of a BPF object or the PID of a process. Node colors represent the subtype of the BPF object, e.g., the map type for maps.

The plugin outputs the graph in .dot and .png format.

## Developer Documentation

This plugin has no public interface.

## Technical Documentation

This plugin uses the `bpf_list(progs|maps|links|procs)` plugins to generate a graph with the properties described above. We use networkx to assemble the graph and pygraphviz for serialization, layout and rendering.
