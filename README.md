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

[Nile Testnet proposal plans](https://github.com/tron-nile-testnet/nile-proposal) You can view the nile proposal discussions and plans.


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

Running java-tron requires 64-bit version of `Oracle JDK 1.8` to be installed, other JDK versions are not supported yet. Make sure you operate on `Linux` and `MacOS` operating systems.

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

- Full node has full historical data, it is the entry point into the TRON Nile test network , it can be used by other processes as a gateway into the TRON nile test network via HTTP and GRPC endpoints. You can interact with the TRON Nile test network through full node：transfer assets, deploy contracts, interact with contracts and so on.
- `-c` parameter specifies a configuration file to run a full node:
[nile_testnet_config.conf](https://github.com/tron-nile-testnet/nile-testnet/blob/master/framework/src/main/resources/config-nile.conf).
- `-d` parameter specifies a nile database. [nile_database_resource](https://database.nileex.io/).

```bash
 $ nohup java -Xms9G -Xmx9G -XX:ReservedCodeCacheSize=256m \
             -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=512m \
             -XX:MaxDirectMemorySize=1G -XX:+PrintGCDetails \
             -XX:+PrintGCDateStamps  -Xloggc:gc.log \
             -XX:+UseConcMarkSweepGC -XX:NewRatio=2 \
             -XX:+CMSScavengeBeforeRemark -XX:+ParallelRefProcEnabled \
             -XX:+HeapDumpOnOutOfMemoryError \
             -XX:+UseCMSInitiatingOccupancyOnly  -XX:CMSInitiatingOccupancyFraction=70 \
             -jar FullNode.jar -c config-nile.conf >> start.log 2>&1 &
```

# Integrity Check

All jar files available in this release are signed via this GPG key::
  ```
  PUB: BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC
  UID: build@nileex.io
  KeyServer: hkps://keyserver.ubuntu.com
  ```



