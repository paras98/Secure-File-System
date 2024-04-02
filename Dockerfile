# BiBiFi Docker Image - Handout

# Run using
# docker build --tag bibifi .
# docker run --rm -it bibifi
# This should open a ‘bash‘ shell, where the directory containing this
# Dockerfile can be accessed via the ‘/connect‘ directory.
FROM ubuntu:18.04
ENV REFRESH_DATE "2022-09-12"
RUN apt-get update
RUN apt-get dist-upgrade -y

# install dependencies for autolab
RUN apt-get update && apt-get install -y build-essential gcc make sudo

# install dependencies for bibifi
RUN apt-get install -y python3.7
RUN apt-get install -y software-properties-common
RUN apt-get install -y openssl
RUN apt-get install -y libprotobuf-c0-dev libprotobuf-dev libprotoc-dev protobuf-compiler
RUN apt-get install -y clang
RUN apt-get install -y cmake zlib1g-dev libcppunit-dev llvm
RUN apt-get install -y libssl-dev libssh-dev
RUN apt-get install -y libffi-dev libcrypto++-dev
RUN apt-get install -y libmbedtls-dev
RUN apt-get install -y libnacl-dev
RUN apt-get install -y libsodium-dev
RUN apt-get install -y uthash-dev libjansson-dev libgcrypt11-dev

RUN apt-get install -y gcc-multilib

RUN rm /dev/random && ln -s /dev/urandom /dev/random
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir /connect
COPY . /connect
WORKDIR /connect
RUN ls -l 

RUN add-apt-repository universe
RUN sudo apt update
RUN apt-get install -y execstack 

ENTRYPOINT ["./docker_entry.sh"]
