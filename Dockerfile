# Everything is compiled at image build time, on purpose.
#
# `docker run -d image bash -c "CMD"` exec-replaces bash only for a
# single simple command. `./af_xdp_user ...` is simple, so PID 1 is the
# resolver; `gcc x.c && ./x` is compound, so PID 1 stays bash and the
# server is a child. perf stat -p does not follow children, so attaching
# to PID 1 in both arms profiles a real resolver in one and an idle
# shell in the other. Compiling here keeps both arms simple commands.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential clang llvm libbpf-dev libxdp-dev libelf-dev \
	zlib1g-dev pkg-config iproute2 bind9-dnsutils linux-tools-common \
	python3 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dns
COPY . /opt/dns
RUN make && gcc -O2 -Wall -o loadgen loadgen.c

# needs --privileged for XDP; --ulimit memlock=-1 only matters pre-5.11
CMD ["./af_xdp_user", "-d", "eth0", "--filename", "./af_xdp_kern.o", "-w", "8"]
