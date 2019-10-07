#Editing Dockerfile Build File for Master with Java

### Basic build for a radare2 container

To build your own radare2 docker image, cat the code below into a Dockerfile (radare2.docker), and run the following command:
```
docker build - < radare2.docker
```

After the image completes it's build, perform the following command to run it:
```
docker  <image_id> -t -i  /bin/bash
```

**radare2_java.docker**:
```
# using phusion/baseimage as base image.
FROM phusion/baseimage:0.9.9

# Set correct environment variables.
ENV HOME /root

# Regenerate SSH host keys. baseimage-docker does not contain any
RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

# create code directory
RUN mkdir /opt/code/
# install packages required to compile vala and radare2
RUN apt-get update
RUN apt-get install -y software-properties-common python-all-dev wget
RUN apt-get install -y swig flex bison git gcc g++ make pkg-config glib-2.0
RUN apt-get install -y python-gobject-dev python-software-properties
RUN apt-get install -y python-pip jython

# compile vala
RUN cd /opt/code; wget http://download.gnome.org/sources/vala/0.24/vala-0.24.0.tar.xz; tar -Jxf vala-0.24.0.tar.xz
RUN cd /opt/code/vala-0.24.0; ./configure --prefix=/usr ; make && make install
# compile radare
RUN cd /opt/code; git clone https://github.com/radareorg/radare2.git; cd radare2; ./sys/all.sh

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# compile vala
RUN cd /opt/code; wget http://download.gnome.org/sources/vala/0.24/vala-0.24.0.tar.xz; tar -Jxf vala-0.24.0.tar.xz
RUN cd /opt/code/vala-0.24.0; ./configure --prefix=/usr ; make && make install
# compile radare
RUN cd /opt/code; git clone https://github.com/radareorg/radare2.git; cd radare2; ./sys/all.sh


#install oracle jre stuffs
RUN add-apt-repository -y ppa:webupd8team/java
RUN apt-get update
RUN echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections
RUN echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections
RUN apt-get install -y oracle-java7-installer

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
```
