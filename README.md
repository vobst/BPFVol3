# BPFVol3
<img src="https://user-images.githubusercontent.com/89150207/224386992-f97755d1-ccf0-474d-bcd7-6d7f247d9103.jpeg" width=40% height=40%>

## Description

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
### Using the plugin with Docker (recommended)
1. clone this repository
```
git clone https://github.com/vobst/BPFVol3
cd BPFVol3
```
2. build the analysis container
```
./scripts/vol.sh --build
```
2. alternatively: pull the latest image from DockerHub
```
./scripts/vol.sh --pull
```

### Using the plugin with an existing Volatility3 installation
When using this method, it is recommended to stick to the __same__
commit of Volatility3 as the Docker container, see
`scripts/dockerfile_vol` for the current hash.
1. clone this repository
```
git clone https://github.com/vobst/BPFVol3
cd BPFVol3
```
2. copy the files under `source/plugins` to a place where Volatility
can find them, e.g., `${VOLHOME}/volatility3/plugins/linux`,
or make use of the `--plugin-dirs` command line option when
running `vol.py`
3. create the directory `${VOLHOME}/volatility3/utility/`
and copy the contents of `src/utility` into it (set VOLHOME to the root
of your Volatility3 installation)
4. `git apply` all of the patches in `src/patches`

## Getting Started
We assume that you have some memory dump that you want to analyze.
If not, check out the `docs/examples` folder.
1. place the dump in `io/dumps`; you can now read the banner using
```
./scripts/vol.sh --run
vol.py -f /io/dumps/<name_of_dump> banners.Banners
```
2. obtain the ISF file for the kernel in the dump and place it in
`io/symbols`
2. alternatively: download the debug package for the kernel in the dump,
copy the debug kernel and its `System.map` into the `io/kernels`
folder; you can now generate the ISF file yourself
```
./scripts/prepare_kernel.sh <path/to/kernel> <path/to/System.map> --symbols
```
3. start the container and run some plugin
```
./scripts/vol.sh --run
vol.py -f /io/dumps/<name_of_dump> linux.bpf_graph
```

## Documentation
- user manuals for the different plugins can be found in the
`docs/` folder
- case studies (including memory dumps and symbol files) can be found
in the `docs/examples` folder
- below you can get an overview of the project

![project_tree.svg](./docs/media/project_tree.svg)

## Contributing
Bugs report, feature requests and contributions are all highly
welcome :)
Please use the standard GitHub issue/pull request workflow.
