FROM maven:3.3-jdk-8

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

#Start application
WORKDIR /usr/src/mymaven
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
