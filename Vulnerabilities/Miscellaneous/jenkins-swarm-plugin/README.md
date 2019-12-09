## Jenkins Swarm Plugin - XXE (XML External Entities) via UDP broadcast

##### Discovered by:
* Peter Adkins <peter.adkins@kernelpicnic.net>

##### Access:
* Local network; unauthenticated access

##### Tracking and identifiers:
* CVE - CVE-2019-10309

##### Versions Affected:
* Jenkins Swarm-Client 3.14

##### Vendor involvement:
* 2018-12-05 - Vendor Disclosure
* 2019-05-06 - Public Release
* 2019-05-13 - Vendor Patched

##### Notes:

1. Originally published under [TALOS-2019-0783](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0783). Mirrored here here for tracking purposes.

1. Due to the nature of the Java XML parser, files that contain certain characters cannot be reflected in FTP or HTTP URIs to exfiltrate data.

##### Overview:
The Jenkins Self-Organizing Swarm Modules Plugin, version 3.14, contains a trivial XXE (XML External Entities) vulnerability inside of the `getCandidateFromDatagramResponses()` method. As a result of this issue, it is possible for an attacker on the same network as a Swarm client to read arbitrary files from the system by responding to the UDP discovery requests with a specially crafted response.

##### Analysis:

This vulnerability could allow an unprivileged user connected to the network on which a set of Swarm agents are deployed to access data on the agent instances without additional authentication. Due to the nature of the UDP broadcast discovery mechanism, the ability of a user to run the proof-of-concept code in a network that uses this mechanism for Jenkins Master discovery yields unauthenticated local file read(s) on all agents seeking masters. This was tested in a Docker-based environment, where all agents running the Swarm Agent were able to be exploited simultaneously.

This vulnerability exists in the `getCandidateFromDatagramResponses` method of `hudson.plugins.swarm.SwarmClient`, and appears to be due to the processing of DocType declarations from client provided XML.

Please see `exploit.py` and the `Dockerfile` in this directory for a full proof-of-concept and associated test environment.
