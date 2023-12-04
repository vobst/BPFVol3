FROM ubuntu:jammy

ARG VOL_VER
ENV DEBIAN_FRONTEND noninteractive

SHELL ["/bin/bash", "-e", "-u", "-o", "pipefail", "-c"]

RUN set -e 							&& \
    apt-get update 						&& \
    apt-get upgrade -yq 					&& \
    apt-get install -yq --no-install-recommends			\
	build-essential						\
	clang							\
	curl							\
	dwarfdump						\
	elfutils						\
	git							\
	golang-go						\
	graphviz 						\
	graphviz-dev						\
	libssl-dev						\
	llvm							\
	python3							\
	python3-dev						\
	python3-pip						\
	xz-utils						&& \
    python3 -m pip install --upgrade --no-cache-dir pip 	&& \
    apt-get -y autoremove --purge 				&& \
    apt-get clean 						&& \
    rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

WORKDIR /opt/vol
RUN git clone							\
        https://github.com/volatilityfoundation/volatility3.git && \
    cd volatility3						&& \
    git checkout tags/v${VOL_VER}           			&& \
    pip3 install -r requirements-dev.txt			&& \
    pip3 install --no-cache-dir					\
	networkx						\
	pygraphviz

WORKDIR /opt/vol
RUN git clone							\
        https://github.com/volatilityfoundation/dwarf2json 	&& \
    cd dwarf2json						&& \
    go build

WORKDIR /opt/vol/volatility3
RUN mkdir -p volatility3/symbols/linux				&& \
    chmod +x volshell.py
