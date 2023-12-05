# BPFVol3

<img src="https://user-images.githubusercontent.com/89150207/224386992-f97755d1-ccf0-474d-bcd7-6d7f247d9103.jpeg" width=40% height=40%>

## Description

BPFVol3 is a set of [Volatility3](https://github.com/volatilityfoundation/volatility3) plugins for analyzing the [Linux BPF](https://docs.kernel.org/bpf/index.html) subsystem.

Disclaimer: This project is in an __alpha__ state. In particular, it has not been tested in real-world scenarios or reviewed by forensic experts. Do __not__ use it in real-world investigations.

## Requirements

- [Docker](https://docs.docker.com/engine/install/)

## Installation

### Using the plugin with Docker (recommended)

1. Clone this repository

```
git clone https://github.com/vobst/BPFVol3
cd BPFVol3
```

2. Build the analysis container

```
./vol.sh --build
```

2. Alternatively: pull the latest image from the Github Container Registry

```
./vol.sh --pull
```

### Using the plugin with an existing Volatility3 installation

When using this method, it is recommended to stick to the __same__ release of Volatility3 as the Docker container, see `VOL_VER` in `vol.sh`  for the currently supported release.

Note: Set `VOLHOME` to the root of your Volatility3 installation

1. Clone this repository

```
git clone https://github.com/vobst/BPFVol3
cd BPFVol3
```

2. Copy the files under `source/plugins` to a place where Volatility can find them, e.g., `${VOLHOME}/volatility3/plugins/linux`, or make use of the `--plugin-dirs` command line option when running `vol.py`

3. Create the directory `${VOLHOME}/volatility3/utility/` and copy the contents of `src/utility` into it

4. `git apply` the patch in `src/patches`

## Getting Started

We assume that you have some memory image that you want to analyze. If not, check out the `docs/examples` folder.

Note: Commands prefixed with `$` or `#` are executed on the host or in the analysis container, respectively.

1. Place the image in `io/dumps`. You can now read the banner using

```
$ ./vol.sh --run
# ./vol.py -f /io/dumps/<name_of_dump> banners.Banners
```

2. Obtain the ISF file for the kernel in the dump and place it in `io/symbols`

2. Alternatively: Download the debug package for the kernel in the dump, copy the debug kernel and its `System.map` into the `io/kernels` folder. You can now generate the ISF file yourself

```
$ ./scripts/prepare_kernel.sh <path/to/kernel> <path/to/System.map> --symbols
```

3. Start the container and run some plugin

```
$ ./scripts/vol.sh --run
# ./vol.py -f /io/dumps/<name_of_dump> linux.bpf_graph
```

## Documentation

- User manuals for the different plugins can be found in the `docs/` folder
- Case studies (including memory dumps and symbol files) can be found in the `docs/examples` folder
- Below you can get an overview of the project

```
.
├── Dockerfile
├── docs
│   ├── bpf_graph.md
│   ├── bpf_listlinks.md
│   ├── bpf_listmaps.md
│   ├── bpf_listprocs.md
│   ├── bpf_listprogs.md
│   ├── bpf_lsm.md
│   ├── bpf_netdev.md
│   ├── examples
│   │   └── krie
│   │       └── krie.md
│   └── media
│       ├── alpha_logo.jpeg
│       └── krie-3410c66d-26be0e1ef560.elf.png
├── io
│   ├── cache
│   ├── dumps
│   ├── kernels
│   ├── output
│   └── symbols
├── LICENSE.md
├── pyproject.toml
├── README.md
├── scripts
│   ├── bashrc
│   ├── container_init
│   ├── fix_symbols.sh
│   ├── pack_dump.sh
│   └── prepare_kernel.sh
├── src
│   ├── patches
│   │   ├── v2.4.2.patch
│   │   └── v2.5.0.patch
│   ├── plugins
│   │   ├── bpf_graph.py
│   │   ├── bpf_listlinks.py
│   │   ├── bpf_listmaps.py
│   │   ├── bpf_listprocs.py
│   │   ├── bpf_listprogs.py
│   │   ├── bpf_lsm.py
│   │   ├── bpf_netdev.py
│   │   └── ifconfig.py
│   └── utility
│       ├── btf.py
│       ├── datastructures.py
│       ├── enums.py
│       ├── helpers.py
│       ├── link.py
│       ├── map.py
│       └── prog.py
└── vol.sh
```

## Contributing

Bugs report, feature requests and contributions are all highly welcome :)

Please use the standard GitHub issue/pull request workflow.
