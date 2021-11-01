FROM centos@sha256:dbbacecc49b088458781c16f3775f2a2ec7521079034a7ba499c8b0bb7f86875

RUN yum update -y && yum install -y \
    wget git

WORKDIR /src/

RUN git clone https://github.com/NagiosEnterprises/ncpa.git && \
    cd ncpa && \
    git checkout 084fa0ca0f83e051beb5ab93aca349046a9d2d9c

COPY ./src/psapi.py	 /src/ncpa/agent/listener/
COPY ./src/build.sh ./src/rebuild.sh /src/ncpa/build/
COPY ./src/setup.sh /src/ncpa/build/linux/

WORKDIR /src/ncpa/build

RUN ./build.sh

RUN sed 's/_BASEDIR_/BASEDIR=\/usr\/local\/ncpa/' \
    ncpa/build_resources/listener_init > /etc/init.d/ncpa_listener && \
    chmod +x /etc/init.d/ncpa_listener

RUN cp -r ncpa /usr/local/ && \
    chown nagios:nagios /usr/local/ncpa/ -R

RUN sed -i 's/mytoken/rogue_agent_token/' /usr/local/ncpa/etc/ncpa.cfg

CMD /etc/init.d/ncpa_listener start && bash
