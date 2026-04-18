# FlowCoin Reproducible Builds (Gitian)

Gitian is a deterministic build process that allows independent builders
to produce bit-for-bit identical binaries, proving that the distributed
binaries correspond to the public source code.

## Prerequisites

Install Gitian and its dependencies:

```bash
sudo apt-get install git ruby apt-cacher-ng qemu-utils debootstrap \
    lxc python3-cheetah parted kpartx bridge-utils make curl
git clone https://github.com/devrandom/gitian-builder.git
```

## Building

### Linux

```bash
cd gitian-builder
./bin/gbuild --url flowcoin=https://github.com/KristianPilatovich/flowcoin.git \
    --commit flowcoin=v1.0.0 \
    ../flowcoin/contrib/gitian/gitian-linux.yml
```

Output tarballs and SHA256SUMS will be in `gitian-builder/build/out/`.

### macOS (cross-compilation)

Requires the macOS SDK. Extract it from Xcode and place the tarball
in `gitian-builder/inputs/`:

```bash
./bin/gbuild --url flowcoin=https://github.com/KristianPilatovich/flowcoin.git \
    --commit flowcoin=v1.0.0 \
    ../flowcoin/contrib/gitian/gitian-osx.yml
```

## Verifying

Compare your build output SHA256SUMS with those published by other
builders. Identical hashes confirm reproducibility.

```bash
sha256sum -c SHA256SUMS
```
