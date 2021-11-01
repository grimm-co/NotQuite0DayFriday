FROM centos@sha256:dbbacecc49b088458781c16f3775f2a2ec7521079034a7ba499c8b0bb7f86875

# Mandate a password with --build-arg
ARG PASSWORD
RUN ["/bin/bash", "-c", ": ${PASSWORD:?Build argument PASSWORD needs to be set.}"]

RUN yum update -y && yum install -y \
    wget git python2 python3 openssh-server

# Ansible will expect python2
RUN cp `which python2` /usr/bin/python

WORKDIR /src/

COPY ./src/* /src/migrate/

WORKDIR /src/migrate

RUN echo root:$PASSWORD | chpasswd && \
    echo root:$PASSWORD > credentials.txt

RUN ssh-keygen -A
