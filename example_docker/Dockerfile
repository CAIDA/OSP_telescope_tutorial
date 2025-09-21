FROM hub.opensciencegrid.org/htc/ubuntu:22.04
RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install dpkt fsspec argparse
MKDIR /code
MKDIR /output
COPY code/* /code/
ENTRYPOINT ["python3", "/code/ucsdnt-trace.py"]