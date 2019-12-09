FROM ubuntu:latest

# Update repository metadata and install a JVM.
RUN apt update && \
    apt install -y openjdk-8-jre-headless tcpdump curl && \
    apt install -y python3 python3-pip tmux && \
    pip3 install pyftpdlib

# Grab the latest Swarm Client.
RUN curl -D - -o /var/tmp/swarm-client.jar \
    https://repo.jenkins-ci.org/releases/org/jenkins-ci/plugins/swarm-client/3.14/swarm-client-3.14.jar

# Copy our exploit code to the container.
COPY exploit.py /root/exploit.py

# Give 'er.
ENTRYPOINT java -jar /var/tmp/swarm-client.jar
