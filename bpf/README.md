# Bpf programs

## Build

On Ubuntu install:
```bash
sudo apt install -y pkg-config bison binutils-dev build-essential \
        flex libc6-dev clang-12 libllvm12 llvm-12-dev libclang-12-dev \
        zlib1g-dev libelf-dev libfl-dev gcc-multilib zlib1g-dev \
        libcap-dev libiberty-dev libbfd-dev
```

On root directory of the project run:
```bash
make bpf-programs
```

All generated programs will be inside: ./build/dist/bin/bpf/ of root directory.
