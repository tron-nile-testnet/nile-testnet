<h1 align="center">
  <br>
  nile-testnet
  <br>
</h1>

<h4 align="center">
  Java implementation of the <a href="https://tron.network">Tron Protocol</a>
</h4>

<p align="center">
  <a href="https://gitter.im/tronprotocol/allcoredev">
    <img src="https://img.shields.io/gitter/room/tronprotocol/java-tron.svg">
  </a>

  <a href="https://codecov.io/gh/tronprotocol/java-tron">
    <img src="https://codecov.io/gh/tronprotocol/java-tron/branch/develop/graph/badge.svg" />
  </a>

  <a href="https://github.com/tronprotocol/java-tron/issues">
    <img src="https://img.shields.io/github/issues/tronprotocol/java-tron.svg">
  </a>

  <a href="https://github.com/tronprotocol/java-tron/pulls">
    <img src="https://img.shields.io/github/issues-pr/tronprotocol/java-tron.svg">
  </a>

  <a href="https://github.com/tronprotocol/java-tron/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/tronprotocol/java-tron.svg">
  </a>

  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/tronprotocol/java-tron.svg">
  </a>
</p>

## Table of Contents

- [What’s nile-testnet?](#whats-nile-testnet)
- [Community](#community)
- [Building the Source Code](#building-the-source)
- [Running java-tron](#running-java-tron)
- [Contribution](#contribution)
- [Resources](#resources)
- [Integrity Check](#integrity-check)
- [License](#license)

# What's nile-testnet?


nile-testnet is a project for developers to quickly access the tron nile testnet and use the tron nile testnet.

# Community

[Nile Testnet status](https://nileex.io/status/getStatusPage) is Tron's Nile testnet official website. You can find resources for quick access to the Nile testnet.

[Nile Testnet faucet](https://nileex.io/join/getJoinPage) is the faucet for the Nile Testnet. You can claim test coins on this page.

[Nile Testnet proposal status](https://nile.tronscan.org/#/sr/committee) You can view the nile proposals opening situation.

[Nile Testnet proposal plans](https://github.com/tron-nile-testnet/nile-proposal) You can view the nile proposals discussions and plans.


# Building the Source Code

Building java-tron requires `git` package

## Operating systems
Make sure you operate on `Linux` or `MacOS` operating systems, other operating systems are not supported yet.

## Architecture

### x86_64
64-bit version of `Oracle JDK 8` to be installed, other JDK versions are not supported yet.

### ARM64
64-bit version of `JDK 17` to be installed, other JDK versions are not supported yet.

## Build
Clone the repo and switch to the `master` branch

```bash
$ git clone https://github.com/tron-nile-testnet/nile-testnet.git
$ cd nile-testnet
$ git checkout -t origin/master
```

then run the following command to build nile-testnet, the `FullNode.jar` file can be found in `nile-testnet/build/libs/` after build successfully.

```bash
$ ./gradlew clean build -x test
 # To fix DependencyVerificationException: Dependency verification failed for configuration ':xxx' x artifacts failed verification
$ ./gradlew clean --refresh-dependencies --write-verification-metadata sha256

```

# Running nile-testnet

## Operating systems
Make sure you operate on `Linux` or `MacOS` operating systems, other operating systems are not supported yet.

## Architecture

### X86_64
Requires 64-bit version of `Oracle JDK 8` to be installed, other JDK versions are not supported yet.

### ARM64
Requires 64-bit version of `JDK 17` to be installed, other JDK versions are not supported yet.

Get the nile testnet configuration file: [nile_testnet_config.conf](https://github.com/tron-nile-testnet/nile-testnet/blob/master/framework/src/main/resources/config-nile.conf).

## Hardware Requirements

Minimum:

- CPU with 8 cores
- 16GB RAM
- 150GB free storage space

Recommended:

- CPU with 16+ cores
- 32GB+ RAM
- High Performance SSD with at least 200GB free space
- 100+ MB/s download Internet service

## Running a full node for nile testnet

Full node has full historical data, it is the entry point into the TRON network, it can be used by other processes as a gateway into the TRON network via HTTP and GRPC endpoints. You can interact with the TRON network through full node：transfer assets, deploy contracts, interact with contracts and so on. `-c` parameter specifies a configuration file to run a full node:

### x86_64 (JDK 8)
```bash
$ nohup java -Xms9G -Xmx12G -XX:ReservedCodeCacheSize=256m \
             -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=512m \
             -XX:MaxDirectMemorySize=1G -XX:+PrintGCDetails \
             -XX:+PrintGCDateStamps  -Xloggc:gc.log \
             -XX:+UseConcMarkSweepGC -XX:NewRatio=3 \
             -XX:+CMSScavengeBeforeRemark -XX:+ParallelRefProcEnabled \
             -XX:+HeapDumpOnOutOfMemoryError \
             -XX:+UseCMSInitiatingOccupancyOnly  -XX:CMSInitiatingOccupancyFraction=70 \
             -jar FullNode.jar -c config-nile.conf >> start.log 2>&1 &
```
### ARM64 (JDK 17)
```bash
$ nohup java -Xmx9G -XX:+UseZGC \
             -Xlog:gc,gc+heap:file=gc.log:time,tags,level:filecount=10,filesize=100M \
             -XX:ReservedCodeCacheSize=256m \
             -XX:+UseCodeCacheFlushing \
             -XX:MetaspaceSize=256m \
             -XX:MaxMetaspaceSize=512m \
             -XX:MaxDirectMemorySize=1g \
             -XX:+HeapDumpOnOutOfMemoryError \
             -jar FullNode.jar -c config-nile.conf >> start.log 2>&1 &
```

> **Memory Tuning**
> - For 16 GB RAM servers: JDK 8 use `-Xms9G -Xmx12G`; JDK 17 use `-Xmx9G`.
> - For servers with ≥32 GB RAM, suggest setting the maximum heap size (`-Xmx`) to 40 % of total RAM.

## Running a super representative node for mainnet

Adding the `--witness` parameter to the startup command, full node will run as a super representative node. The super representative node supports all the functions of the full node and also supports block production. Before running, make sure you have a super representative account and get votes from others. Once the number of obtained votes ranks in the top 27, your super representative node will participate in block production.

- Full node has full historical data, it is the entry point into the TRON Nile test network , it can be used by other processes as a gateway into the TRON nile test network via HTTP and GRPC endpoints. You can interact with the TRON Nile test network through full node：transfer assets, deploy contracts, interact with contracts and so on.
- `-c` parameter specifies a configuration file to run a full node:
[nile_testnet_config.conf](https://github.com/tron-nile-testnet/nile-testnet/blob/master/framework/src/main/resources/config-nile.conf).
- `-d` parameter specifies a nile database. [nile_database_resource](https://database.nileex.io/).

Fill in the private key of a super representative address into the `localwitness` list in the `config-nile.conf`. Here is an example:

```
 localwitness = [
    <your_private_key>
 ]
```

then run the following command to start the node:
### x86_64 (JDK 8)
```bash
$ nohup java -Xms9G -Xmx12G -XX:ReservedCodeCacheSize=256m \
             -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=512m \
             -XX:MaxDirectMemorySize=1G -XX:+PrintGCDetails \
             -XX:+PrintGCDateStamps  -Xloggc:gc.log \
             -XX:+UseConcMarkSweepGC -XX:NewRatio=3 \
             -XX:+CMSScavengeBeforeRemark -XX:+ParallelRefProcEnabled \
             -XX:+HeapDumpOnOutOfMemoryError \
             -XX:+UseCMSInitiatingOccupancyOnly  -XX:CMSInitiatingOccupancyFraction=70 \
             -jar FullNode.jar --witness -c config-nile.conf >> start.log 2>&1 &
```
### ARM64 (JDK 17)
```bash
$ nohup java -Xms9G -Xmx9G -XX:+UseZGC \
             -Xlog:gc,gc+heap:file=gc.log:time,tags,level:filecount=10,filesize=100M \
             -XX:ReservedCodeCacheSize=256m \
             -XX:+UseCodeCacheFlushing \
             -XX:MetaspaceSize=256m \
             -XX:MaxMetaspaceSize=512m \
             -XX:MaxDirectMemorySize=1g \
             -XX:+HeapDumpOnOutOfMemoryError \
             -jar FullNode.jar --witness -c main_net_config.conf >> start.log 2>&1 &
```

## Quick Start Tool

### x86_64 (JDK 8)
An easier way to build and run java-tron is to use `start.sh`. `start.sh` is a quick start script written in the Shell language. You can use it to build and run java-tron quickly and easily.

Here are some common use cases of the scripting tool

- Use `start.sh` to start a full node with the downloaded `FullNode.jar`
- Use `start.sh` to download the latest `FullNode.jar` and start a full node.
- Use `start.sh` to download the latest source code and compile a `FullNode.jar` and then start a full node.

For more details, please refer to the tool [guide](./shell.md).

### ARM64 (JDK 17)
You can refer to the [start.sh.simple](start.sh.simple).

```bash
# cp start.sh.simple start.sh
# Usage:
#   sh start.sh           # Start the java-tron FullNode
#   sh start.sh -s        # Stop the java-tron FullNode
#   sh start.sh [options] # Start with additional java-tron options,such as: -c config.conf -d /path_to_data, etc.
#
```

## Run inside Docker container

One of the quickest ways to get `java-tron` up and running on your machine is by using Docker:

```shell
$ docker run -d --name="java-tron" \
             -v /your_path/output-directory:/java-tron/output-directory \
             -v /your_path/logs:/java-tron/logs \
             -p 8090:8090 -p 18888:18888 -p 50051:50051 \
             tronprotocol/java-tron \
             -c /java-tron/config/main_net_config.conf
```

This will mount the `output-directory` and `logs` directories on the host, the docker.sh tool can also be used to simplify the use of docker, see more [here](docker/docker.md).

# Community

[Tron Developers & SRs](https://discord.gg/hqKvyAM) is Tron's official Discord channel. Feel free to join this channel if you have any questions.

The [Core Devs Community](https://t.me/troncoredevscommunity) and [Tron Official Developer Group](https://t.me/TronOfficialDevelopersGroupEn) are Telegram channels specifically designed for java-tron community developers to engage in technical discussions.

[tronprotocol/allcoredev](https://gitter.im/tronprotocol/allcoredev) is the official Gitter channel for developers.

# Contribution

Thank you for considering to help out with the source code! If you'd like to contribute to java-tron, please see the [Contribution Guide](./CONTRIBUTING.md) for more details.

# Resources

- [Medium](https://medium.com/@coredevs) java-tron's official technical articles are published there.
- [Documentation](https://tronprotocol.github.io/documentation-en/) and [TRON Developer Hub](https://developers.tron.network/) serve as java-tron’s primary documentation websites.
- [Test network](http://nileex.io/) A stable test network of TRON contributed by TRON community.
- [Tronscan](https://tronscan.org/#/) TRON network blockchain browser.
- [Wallet-cli](https://github.com/tronprotocol/wallet-cli) TRON network wallet using command line.
- [TIP](https://github.com/tronprotocol/tips) TRON Improvement Proposal (TIP) describes standards for the TRON network.
- [TP](https://github.com/tronprotocol/tips/tree/master/tp) TRON Protocol (TP) describes standards already implemented in TRON network but not published as a TIP.

# Integrity Check

All jar files available in this release are signed via this GPG key::
  ```
  PUB: BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC
  UID: build@nileex.io
  KeyServer: hkps://keyserver.ubuntu.com
  ```

# License

java-tron is released under the [LGPLv3 license](https://github.com/tronprotocol/java-tron/blob/master/LICENSE).
