<h1 align="center">
  <br>
  nile-testnet
  <br>
</h1>


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

Building java-tron requires `git` package and 64-bit version of `Oracle JDK 1.8` to be installed, other JDK versions are not supported yet. Make sure you operate on `Linux` and `MacOS` operating systems.

Clone the repo and switch to the `master` branch

```bash
$ git clone https://github.com/tron-nile-testnet/nile-testnet.git
$ cd nile-testnet
$ git checkout -t origin/master
```

then run the following command to build nile-testnet, the `FullNode.jar` file can be found in `nile-testnet/build/libs/` after build successfully.

```bash
$ ./gradlew clean build -x test
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

# Integrity Check

All jar files available in this release are signed via this GPG key::
  ```
  PUB: BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC
  UID: build@nileex.io
  KeyServer: hkps://keyserver.ubuntu.com
  ```

# License

java-tron is released under the [LGPLv3 license](https://github.com/tronprotocol/java-tron/blob/master/LICENSE).

