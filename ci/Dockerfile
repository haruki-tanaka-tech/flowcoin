# FlowCoin CI build environment
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    python3 \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies for functional tests
RUN pip3 install --no-cache-dir pycryptodome

WORKDIR /flowcoin
COPY . .

RUN mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

CMD ["./build/flowcoin_tests"]
