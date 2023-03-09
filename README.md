# BPFVol3
BPFVol3 is a set of
[Volatility3](https://github.com/volatilityfoundation/volatility3)
plugins for analyzing the
[Linux BPF](https://docs.kernel.org/bpf/index.html) subsystem.

Disclaimer: This project is in an __alpha__ state. In particular, it has
not been tested in real-world scenarios or reviewed by
forensic experts. Do __not__ use it in real-world investigations.

## Requirements
- [Docker](https://docs.docker.com/engine/install/)

## Installation
1. clone this repository
```
git clone https://github.com/vobst/BPFVol3
cd BPFVol3
```
2. build the analysis container
```
./scripts/vol.sh --build
```
2. Alternatively: Pull the latest image from DockerHub
```
./scripts/vol.sh --pull
```

## Getting Started
We assume that you have some memory dump that you want to analyze.
If not, check out the `./docs/examples` folder.
1. place the dump in `io/dumps`
2. obtain the ISF file for the kernel in the dump and place it in
`./io/isf`. You can read the banner using
```
./scripts/vol.sh --run
vol -f /io/dumps/<name_of_dump> banners.Banners
```
2. Alternatively: download the debug package for the kernel in the dump,
copy the debug kernel and its `System.map` into the `./io/kernels`
folder. Next, generate the ISF file
```
./scripts/prepare_kernel.sh <path/to/kernel> <path/to/System.map> --isf
```
3. start the container and run some plugin, any files that produced by
the analysis can be found under the `./io/output` folder
```
./scripts/vol.sh --run
vol -f /io/dumps/<name_of_dump> linux.bpf_graph
```

## Documentation
- user manuals for the different plugins can be found in the
`docs/` folder
- case studies (including memory dumps and symbol files) can be found
in the `./docs/examples` folder
- below you can get an overview of the project

![project_tree.svg](./docs/media/project_tree.svg)

## Contributing
Bugs report, feature requests and contributions are all highly
welcome :)
Please use the standard GitHub issue/pull request workflow.
