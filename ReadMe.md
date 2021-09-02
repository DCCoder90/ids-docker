# IDS-Docker

[![Build Image](https://github.com/DCCoder90/ids-docker/actions/workflows/build-check.yml/badge.svg)](https://github.com/DCCoder90/ids-docker/actions/workflows/build-check.yml)
[![Build Docker Image](https://github.com/DCCoder90/ids-docker/actions/workflows/docker-build.yml/badge.svg)](https://github.com/DCCoder90/ids-docker/actions/workflows/docker-build.yml)

## Configuration

Name|Value Type|Description
---|---|---
UsersConnStr|String|Connection string to users store
ConfigConnStr|String|Connection string to ids configuration store
OperationalConn|String|Connection string to ids operational store
Migrate|Bool|If set to true, migrate database