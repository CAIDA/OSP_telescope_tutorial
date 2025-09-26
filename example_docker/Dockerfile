FROM hub.opensciencegrid.org/htc/ubuntu:22.04
RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install dpkt fsspec argparse pycryptodome pelicanfs
RUN mkdir /code
RUN mkdir /output
COPY code/* /code/
WORKDIR /code
RUN chmod +x ucsdnt-trace.py
ENTRYPOINT ["/code/ucsdnt-trace.py"]
