#
# 	Copyright (c) 2026, VeriSign, Inc.
# 	All rights reserved.
#
# 	Redistribution and use in source and binary forms, with or without
# 	modification, are permitted (subject to the limitations in the disclaimer
# 	below) provided that the following conditions are met:
#
# 		* Redistributions of source code must retain the above copyright notice,
# 		this list of conditions and the following disclaimer.
#
# 		* Redistributions in binary form must reproduce the above copyright
# 		notice, this list of conditions and the following disclaimer in the
# 		documentation and/or other materials provided with the distribution.
#
# 		* Neither the name of the copyright holder nor the names of its
# 		contributors may be used to endorse or promote products derived from this
# 		software without specific prior written permission.
#
# 	NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
# 	THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# 	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# 	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# 	PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# 	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# 	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# 	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# 	BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# 	IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# 	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# 	POSSIBILITY OF SUCH DAMAGE.
#

# Use the pqc_base image that has the depenencies available
FROM pqc_mtl_mode:latest

USER root
RUN dnf -y install gcc autoconf libtool expat-devel tcpdump bison net-tools iputils flex bind-utils vim

# Set the working directory in the container
RUN mkdir -p /usr/local/app
WORKDIR /usr/local/app

#######################################
# Build the LDNS Library with the PQC extensions
#######################################
COPY ./src /usr/local/app

RUN libtoolize -ci && \
    autoreconf -fi && \
    ldconfig -v && \
    ./configure --prefix=/usr/local --enable-pqc-algo-fl-dsa --enable-pqc-algo-ml-dsa --enable-pqc-algo-slh-dsa-sha2 \
                --enable-pqc-algo-slh-dsa-shake --enable-pqc-algo-mayo-1 --enable-pqc-algo-mayo-2 \
                --enable-pqc-algo-snova --enable-pqc-algo-mtl-mode && \
    make && \
    make install

# Copy over unbound's configuration file(s)
RUN mkdir -p /usr/local/etc/unbound/log /app 
COPY docker/config/unbound.conf /usr/local/etc/unbound/unbound.conf
COPY docker/config/root.hints /usr/local/etc/unbound/root.hints
COPY docker/docker-entrypoint.sh /
COPY docker/test.sh /app
RUN chmod -R 755 /app/test.sh /docker-entrypoint.sh


# Setup unbound permissions (to run as non-root)
RUN groupadd unbound && useradd -g unbound -s /etc -d /usr/unbound unbound
RUN chmod 755 /usr/local/etc/*
RUN chown -R unbound:unbound /usr/local/etc/unbound

WORKDIR /usr/local/etc/unbound

# Export DNS ports
EXPOSE 53/tcp
EXPOSE 53/udp

ENTRYPOINT ["/docker-entrypoint.sh"]