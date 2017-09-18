# Development
FROM ubuntu:16.04

ARG uid=1000
ARG user=indy

# Install environment
RUN apt-get update -y
RUN apt-get install -y \ 
	git \
	wget \
	python3.5 \
	python3-pip \
	python-setuptools \
	python3-nacl \
	apt-transport-https \
	ca-certificates \
	zip \
	unzip
RUN pip3 install -U \ 
	pip \ 
	setuptools \
	virtualenv
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 68DB5E88
RUN echo "deb https://repo.sovrin.org/deb xenial master" >> /etc/apt/sources.list
ADD setup-charm.sh setup-charm.sh
RUN bash setup-charm.sh
RUN useradd -ms /bin/bash -u $uid $user
USER $user
RUN virtualenv -p python3.5 /home/$user/test
USER root
RUN ln -sf /home/$user/test/bin/python /usr/local/bin/python
RUN ln -sf /home/$user/test/bin/pip /usr/local/bin/pip
USER $user
WORKDIR /home/$user
