# radare2_go.docker
Dockerfile Build File for Master with Go
###Basic build for a radare2 container

To build your own radare2 docker image, cat the code below into a Dockerfile (radare2.docker), and run the following command:
```
docker build - < radare2_go.docker
```
After the image completes it's build, perform the following command to run it:
```
docker  <image_id> -t -i  /bin/bash
```
Or you can just pull it 

```
docker pull xn0px90/radare2_go
```
It is composed of two files:
- dockerfile 
- go-wrapper 

**radare2_go.docker**;
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
RUN mkdir -p /opt/code/
# install packages required to compile vala and radare2
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y software-properties-common python-all-dev wget
RUN apt-get install -y swig flex bison git gcc g++ make pkg-config glib-2.0
RUN apt-get install -y python-gobject-dev valgrind gdb

ENV VALA_TAR vala-0.26.1

# compile vala
RUN cd /opt/code && \
	wget -c https://download.gnome.org/sources/vala/0.26/${VALA_TAR}.tar.xz && \
	shasum ${VALA_TAR}.tar.xz | grep -q 0839891fa02ed2c96f0fa704ecff492ff9a9cd24 && \
	tar -Jxf ${VALA_TAR}.tar.xz
RUN cd /opt/code/${VALA_TAR}; ./configure --prefix=/usr ; make && make install
# compile radare and bindings
RUN cd /opt/code; git clone https://github.com/radareorg/radare2.git; cd radare2; ./sys/all.sh

#install Go

ENV GOLANG_VERSION 1.6.2
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 e40c36ae71756198478624ed1bb4ce17597b3c19d243f3f0899bb5740d56212a

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
	&& echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf golang.tar.gz \
	&& rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

COPY go-wrapper /usr/local/bin/
#debugging Go apps with dlv DWARF spec th eright way
RUN go get github.com/derekparker/delve/cmd/dlv 

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


RUN r2 -V


```

***go-wrapper***:
```
#!/bin/bash
set -e

usage() {
	base="$(basename "$0")"
	cat <<EOUSAGE
usage: $base command [args]
This script assumes that is is run from the root of your Go package (for
example, "/go/src/app" if your GOPATH is set to "/go").
In Go 1.4, a feature was introduced to supply the canonical "import path" for a
given package in a comment attached to a package statement
(https://golang.org/s/go14customimport).
This script allows us to take a generic directory of Go source files such as
"/go/src/app" and determine that the canonical "import path" of where that code
expects to live and reference itself is "github.com/jsmith/my-cool-app".  It
will then ensure that "/go/src/github.com/jsmith/my-cool-app" is a symlink to
"/go/src/app", which allows us to build and run it under the proper package
name.
For compatibility with versions of Go older than 1.4, the "import path" may also
be placed in a file named ".godir".
Available Commands:
  $base download
  $base download -u
    (equivalent to "go get -d [args] [godir]")
  $base install
  $base install -race
    (equivalent to "go install [args] [godir]")
  $base run
  $base run -app -specific -arguments
    (assumes "GOPATH/bin" is in "PATH")
EOUSAGE
}

# "shift" so that "$@" becomes the remaining arguments and can be passed along to other "go" subcommands easily
cmd="$1"
if ! shift; then
	usage >&2
	exit 1
fi

goDir="$(go list -e -f '{{.ImportComment}}' 2>/dev/null || true)"

if [ -z "$goDir" -a -s .godir ]; then
	goDir="$(cat .godir)"
fi

dir="$(pwd -P)"
if [ "$goDir" ]; then
	goPath="${GOPATH%%:*}" # this just grabs the first path listed in GOPATH, if there are multiple (which is the detection logic "go get" itself uses, too)
	goDirPath="$goPath/src/$goDir"
	mkdir -p "$(dirname "$goDirPath")"
	if [ ! -e "$goDirPath" ]; then
		ln -sfv "$dir" "$goDirPath"
	elif [ ! -L "$goDirPath" ]; then
		echo >&2 "error: $goDirPath already exists but is unexpectedly not a symlink!"
		exit 1
	fi
	goBin="$goPath/bin/$(basename "$goDir")"
else
	goBin="$(basename "$dir")" # likely "app"
fi

case "$cmd" in
	download)
		execCommand=( go get -v -d "$@" )
		if [ "$goDir" ]; then execCommand+=( "$goDir" ); fi
		set -x; exec "${execCommand[@]}"
		;;
		
	install)
		execCommand=( go install -v "$@" )
		if [ "$goDir" ]; then execCommand+=( "$goDir" ); fi
		set -x; exec "${execCommand[@]}"
		;;
		
	run)
		set -x; exec "$goBin" "$@"
		;;
		
	*)
		echo >&2 'error: unknown command:' "$cmd"
		usage >&2
		exit 1
		;;
esac

``` 
