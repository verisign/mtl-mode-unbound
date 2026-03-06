#!/usr/bin/env bash

echo "Starting Unbound Recursive Resolver"

__setup_root_hints() {
    if [ -z ${ROOT_NS_IP} ]
    then
        echo "Automatically setting Registry IP to default"
        ROOT_NS_IP=192.168.1.50
    else
        echo "Using user value for Registry IP"
    fi

    echo "IP of the root service is ${ROOT_NS_IP}"
    sed -i '/^ns/d' /usr/local/etc/unbound/root.hints
    echo "ns1.    3600    IN  A   ${ROOT_NS_IP}" >> /usr/local/etc/unbound/root.hints
    echo "ns2.    3600    IN  A   ${ROOT_NS_IP}" >> /usr/local/etc/unbound/root.hints
    chmod 755 /usr/local/etc/unbound/root.hints
}

__update_trust_anchor() {
    sed -i "/trust-anchor:/c\    trust-anchor: \"$TRUST_ANCHOR\"" /usr/local/etc/unbound/unbound.conf
}

__run_unbound() {
    /usr/local/sbin/unbound -d -c /usr/local/etc/unbound/unbound.conf
}

__setup_root_hints
__update_trust_anchor
__run_unbound
