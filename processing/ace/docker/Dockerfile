FROM node:8-slim

# See https://crbug.com/795759
RUN apt-get update && apt-get install -yq libgconf-2-4

# Install Python & tools
RUN apt-get update && apt-get install -y python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge --auto-remove -y curl \
    && rm -rf /src/*.deb

# Install ACE library
RUN pip3 install acefile

COPY ace-extract.py /
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["/ace-extract.py", "--"]
