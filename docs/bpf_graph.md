# Visualize the state of BPF

## User Documentation

The purpose of this plugin is to display the combined analysis results
in a human-friendly way. We intend this to be a quick way to get a
high-level overview of the state of the BPF subsystem.

Nodes are either:

- processes that hold BPF some resource
- maps
- programs

Edges are either indicating that a:

- program uses a map
- process holds an fd for a BPF object

Node labels and properties provide more information on the object they
represent, e.g., where a program is attached.

Node colors represent the subtype of the object, e.g., the map type for
maps.

## Technical Documentation

Just call all the plugins and use networkx to build a graph.
