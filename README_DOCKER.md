# PQC Unbound Docker Images
The PQC Unbound image is dependent on the MTL Mode base image which consists of MTL Mode (version 1.3.0), OpenSSL (version 3.5.0+) and LibOQS (version 0.16.0+).

That base image can be built using the MTL repository: (https://github.com/verisign/MTL) using branch v1.3.0

## Building
The MTL Mode container is built using docker and defaults to enabling several underlying signature schemes listed in [README_SCHEMES.md](./README_SCHEMES.md).

The container is built using the compose.yaml file for docker compose:

``` docker compose build```

Alternatively it can be built directly with docker using the labels and parameters defined in the compose.yaml file.

# Running
The resulting container contains runnable version of unbound. Because a recursive resolver depends on having access to an authoritative server, the compose.yaml file configures the network and includes a copy of the NSD MTL container (from the repository: (https://github.com/verisign/mtl-mode-nsd)) that maps the zones directory to the zones directory in the NSD container. NSD is configured to run on the DNS standard port 53, while Unbound is configured to run on port 5553 to avoid any conflicts on local ports.

The container can be started with the following command

 ``` docker compose up ``` 

_Note: See the NSD container for more information on how that container is built or configured_
