# v1f
FROM debian:bullseye
ARG CERT_FILE="10ZiG_SecureBoot2.der"

# dependencies
RUN apt-get -y -qq update
RUN apt-get -y -qq install gcc make bzip2 efitools curl wget git
# 
# clone shim
WORKDIR /build
RUN mkdir -p /build/patches
COPY patches /build/patches

RUN wget https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2
RUN tar jxf shim-15.7.tar.bz2
WORKDIR /build/shim-15.7

RUN git apply /build/patches/*.patch

# include certificate and custom sbat
ADD ${CERT_FILE} .
ADD shimx64_10ZiG.sbat .

# append sbat data to the upstream data/sbat.csv
RUN cat shimx64_10ZiG.sbat >> data/sbat.csv && cat data/sbat.csv

# build
RUN mkdir build-x64
RUN make -C build-x64 ARCH=x86_64 VENDOR_CERT_FILE=../${CERT_FILE} TOPDIR=.. -f ../Makefile

# output
RUN mkdir /build/output
RUN cp build-x64/shimx64.efi /build/output
RUN cp ${CERT_FILE} /build/output
RUN objdump -s -j .sbatlevel /build/output/shimx64.efi
RUN objdump -j .sbat -s /build/output/shimx64.efi
RUN sha256sum /build/output/*
