# Unbound Customized for MTL research

This repo contains a customized version of Unbound that implements draft [draft-kaizer-dnsop-ml-dsa-mtl-dnssec-02](https://datatracker.ietf.org/doc/draft-kaizer-dnsop-ml-dsa-mtl-dnssec/).

This version also includes the extension specified in [draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext-00](https://datatracker.ietf.org/doc/draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext/). The extension is managed via the unbound.conf file.

To enable sigtags
```
enable-edns-sigtag-mtl: yes
```

To disable sigags
```
enable-edns-sigtag-mtl: no
```


# Build

See the [README_DOCKER](README_DOCKER.md) file for more information on building and running this version of NSD.
