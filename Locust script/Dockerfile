FROM locustio/locust:2.32.2

COPY locustfile.py /mnt/locust/
WORKDIR /mnt/locust

# Default command will run locust
CMD ["-f", "locustfile.py"]
