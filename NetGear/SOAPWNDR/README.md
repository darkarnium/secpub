## NetGear WNDR Authentication Bypass / Information Disclosure

##### Discovered by:
* Peter Adkins &lt;peter.adkins@kernelpicnic.net&gt;

##### Access:
* Local network; unauthenticated access.
* Remote network; unauthenticated access.

##### Tracking and identifiers:
* CVE - Mitre contacted; none yet allocated.

##### Platforms / Firmware confirmed affected:
* NetGear WNDR3700v4 - V1.0.0.4SH
* NetGear WNDR3700v4 - V1.0.1.52
* NetGear WNR2200 - V1.0.1.88
* NetGear WNR2500 - V1.0.0.24

##### Additional platforms believed to be affected:
* NetGear WNDR3800
* NetGear WNDRMAC
* NetGear WPN824N
* NetGear WNDR4700

##### Vendor involvement:
* 2015-01-18 - Initial contact with NetGear regarding vulnerability.
* 2015-01-18 - NetGear advised to email support with concerns.
* 2015-01-18 - Email sent to NetGear (support).
* 2015-01-19 - Email sent to Mitre.
* 2015-01-20 - NetGear (support) advised that a ticket had been created.
* 2015-01-21 - NetGear (support) requested product verification.
* 2015-01-21 - Replied to NetGear with information requested.
* 2015-01-23 - NetGear (support) requested clarification of model.
* 2015-01-23 - Replied to NetGear with list of affected models.
* 2015-01-27 - NetGear (support) replied with router security features.
* 2015-01-27 - Replied to NetGear and reiterated vulnerability.
* 2015-01-29 - Email sent to NetGear (OpenSource) regarding issue.
* 2015-01-30 - Case auto-closure email received from NetGear (support).
* 2015-02-01 - Reply from Mitre requesting additional information.
* 2015-02-01 - Email to Mitre with additional information.
* 2015-02-11 - Vulnerability published to Bugtraq.

##### Notes:
1. Due to the location of this issue (net-cgi and uhttpd) this vulnerability may be present in other devices and firmware revisions not listed in this document.

2. These vulnerabilities can be leveraged "externally" over the internet, but require devices to have remote / WAN management enabled.

3. In the absence of a known security contact these issues were reported to NetGear support. The initial response from NetGear support was that despite these issues "the network should still stay secure" due to a number of built-in security features. Attempts to clarify the impact of this vulnerability with support were unsuccessful. This ticket has since been auto-closed while waiting for a follow up. A subsiquent email sent to the NetGear 'OpenSource' contact has also gone unanswered.

4. If you have a NetGear device that is believed to be affected and can confirm whether the PoC works successfully, let me know and I will update this document accordingly with credit provided to you.

### Overview

A number of WNDR series devices contain an embedded SOAP service for use with the NetGear Genie application. This service allows for viewing and setting of certain router parameters, such as:

* WLAN credentials and SSIDs.
* Connected clients.
* Guest WLAN credentials and SSIDs.
* Parental control settings.

At first glance, this service appears to be filtered and authenticated; HTTP requests with a `SOAPAction` header set but without a session identifier will yield a HTTP 401 error. However, a HTTP POST with as little as a blank form and a `SOAPAction` header is sufficient to execute certain requests and query information from the device.

As this SOAP service is called via the built-in HTTP / CGI daemon, unauthenticated queries will be answered from the WAN if remote management has been enabled on the device. As a result, affected devices can be interrogated and hijacked with as little as a well placed HTTP query.

The included proof of concept queries this service in order to extract the admin password, device serial number, WLAN details, and various information regarding clients currently connected to the device.

### Analysis :: uHTTPd

In the case of the WNDR3700v4 - as other devices may utilize a different arrangement - the under-laying system is built on-top of OpenWRT. As part of this, the OpenWRT uhttpd service is being used to serve up the management interface on this device. This said, NetGear specific functionality is implemented via an ELF binary called through the uhttpd CGI provider.

Although there are a few NetGear patches inside of the uhttpd codebase, the vulnerability exists inside the custom CGI provider and not the OpenWRT uhttpd service.

If we review an abridged version of the uhttpd code - taken from the NetGear WNDR3700v4 GPL package - we can see that when the application is loaded, `uh_config_parse` is called (line 735) and a loop to handle client connections is started (line 818).

![uhttpd-main](/images/uhttpd-main.png)

When a HTTP request comes in `uh_path_lookup` is called to evaluate the requested URL (line 921). If the request path is found to be invalid by this lookup the rest of the block is bypassed and a 404 returned to the client (line 952).

Further to this, due to some wacky routing happening at line 931, all we need to do is request a resource that exists and doesn't have `.gif`, `.jpg`, or `.css` somewhere in the filename and `ug_cgi_request` will be called.

Interestingly enough, `uh_auth_check` (line 924) is doing absolutely nothing here; we could replace this call with an `if(true)` and achieve the same functionality. This is not the fault of the uhttpd service but rather the lack of realm configuration on the device. If we rewind a bit to `uh_config_parse` we can see why.

![uhttpd-config-parse](/images/uhttpd-config-parse.png)

The `uh_auth_add` function, which populates the realm array, is called per line of realm configuration from either the configuration file specified as a command argument or a default of `/etc/httpd.conf`.

However, if we inspect the `uhttpd.sh` init script on the device we can see that no configuration file path is specified at daemon start. If we also check for the presence of the default file - being `/etc/httpd.conf` - we find it to be missing.

This ends in a realm blank array. As a result of this, all documents bypass uhttpd build-in authentication - due to the `uh_auth_check` returning `true` by default.

![uhttpd-sh](/images/uhttpd-sh.png)

Based on this information, and the location of the authentication data in SOAP envelopes from "Genie" client, we can ascertain that authentication is being handled by the `net-cgi` process directly.

### Analysis :: Net-CGI

As found above, the `net-cgi` process seems to be called for almost all documents, and is in charge of both authentication and processing of CGI requests. The `net-cgi` process itself is an ELF binary that is called through the uhttpd CGI wrapper; specifically by an `execl()` (line 429) inside of the `uh_cgi_request` function:

![uhttpd-cgi](/images/uhttpd-cgi.png)

All pertinent HTTP headers - and a few others that are hidden in this excerpt - are passed through environment variables to `net-cgi`. Included in these headers are the two that we are interested in: `SOAPAction` (line 420) and `Authorization` (line 396).

As we're now hitting a binary that we do not have sources for we will need to start debugging the process directly. In order to do this, we will be using `gdb`, `binutils` and `radare2`. Lucky for us however, the GPL package from NetGear includes a pre-compiled `net-cgi` with debugging symbols.

To start, we need to work out where we are in the world. In order to do so, let's look for somewhere that we can attach a breakpoint to and then trace backwards from.

![net-cgi-readelf](/images/net-cgi-readelf.png)

There are a few interesting looking results here, so let's get started with those most likely related to the execution of SOAP requests, namely `ExecuteSoapAction` and `SendSoapResponse`. We'll start by attaching a breakpoint to `ExecuteSoapAction` (`0x00429f88`) and submit a known-working SOAP call to the device (`GetInfo` from the `LANConfigSecurity` namespace).

![net-cgi-gdb-bp1](/images/net-cgi-gdb-bp1.png)

...that's exactly what we want to see; we're hitting our installed breakpoint as expected. If we inspect a trace leading up to the breakpoint we can see that `ExecuteSoapAction` is called via `handle_http_request`, so it looks like we're on the right track.

Let's attach breakpoints to all of the addresses we found related to authentication and give the same request another shot.

![net-cgi-gdb-bp2](/images/net-cgi-gdb-bp2.png)

As we're hitting the same breakpoint as above, it looks like authentication is handled either inside of `ExecuteSoapAction` or afterwards. Let's remove the `ExecuteSoapAction` breakpoint and try again. 

![net-cgi-gdb-bp3](/images/net-cgi-gdb-bp3.png)

Err, righto, we didn't hit any breakpoints... Let's try a different SOAP action instead. This time we'll try with `Authenticate` from inside the `ParentalControl` namespace - which is used as part of initial authentication envelope sent by the "Genie" application.

![net-cgi-gdb-bp4](/images/net-cgi-gdb-bp4.png)

Finally, there's the breakpoint we were expecting to see. The real question is why we're not hitting this break-point unless we submit a SOAP action inside of the `ParentalControl` namespace.

First though, let's work out where we are and how we got there.

If we look at the trace, and the contents of the `ra` register, we can see that `soap_auth` is being called from `ExecuteSoapAction` at `0x0042a184`. If we compare this with previous traces, and the contents of the `ra` registers at each step, we find that we're kicked to `ExecuteSoapAction` (`0x00429f88`) by `0x00407b5c` inside of `handle_http_request`. As this is exactly the same behaviour we've seen with other SOAP actions - except for the final kick to `soap_auth` - we're likely being routed through the application in a consistent manner up until this point.
 
 Now that we know how we're getting from `handle_http_request` to `soap_auth`, the question is why we only hit `soap_auth` during a SOAP call that lives inside the `ParentalControl` namespace.

 Once we've traced through and commented as much of `ExecuteSoapAction` as we can, it becomes quite clear what's causing this.

![ExecuteSoapAction-SOAPActions](/images/ExecuteSoapAction-SOAPActions.png)

At `0x00429fe4` the program seems to load the address of a `SOAPActions` array into argument register `a0`. At `0x00429fec` it then performs a 'safety check' to ensure that the array it just loaded is non-zero.

Assuming the array was loaded, we're then branched to a `jalr` at `0x0042a00c` which jumps to the address of `strcmp()` - via `libc`. This `strcmp()` is testing whether the first element of the `SOAPActions` array we just loaded matches the SOAP namespace specified in the `SOAPAction` header from the client.

As per the comment above `0x0042a014`, if this test fails - as the strings aren't a match - then we are branched back up to `0x00429ffc` where the address is incremented to the next element inside of `SOAPActions`. A quick test is performed at `0x0042a004` to ensure the new address is valid, and the whole process is performed again.

Interestingly, even after this lookup has been completed, a separate `strcmp()` is performed at `0x0042a02c` to check whether the client specified SOAP namespace is `ParentalControl`. This seems to be where the `soap_auth` is referenced, and why authentication is only required for `ParentalControl` calls.

The process described above can be very roughly expressed as something like following pseudo-code:

```
SOAPActions = Array("DeviceConfig", ... "ParentalControl")

function ExecuteSoapAction(SOAPNamespace, SOAPCall, ContentLength) {

  if length of ContentLength is zero {
    call SendSoapRespCode(401)
  }
  if length of SOAPNamespace is zero {
    call SendSoapRespCode(401)
  }
  if length of SOAPCall is zero {
    call SendSoapRespCode(401)
  }

  SOAPActionFound = false
  for each entry in SOAPActions as SOAPAction {
    if SOAPAction == SOAPNamepsace {
      SOAPActionFound = true
      break
    }
  }

  if SOAPNamepsace == "ParentalControl" {
    SOAPActionFound = true
    call soap_auth()
  }

  if not SOAPActionFound {
    call SendSoapRespCode(401)
  }

  ...
}
```

Now that we know why `soap_auth` is only called for `ParentalControl`, the final question is why we receive a SOAP 401 message when we attempt to call a valid SOAP action with a blank request.

...Long story short, `0x00429fdc` is responsible for this.

![ExecuteSoapAction-ContentLength](/images/ExecuteSoapAction-ContentLength.png)

The `beqz` operation at `0x00429fdc` is being used to ensure that the content-length HTTP header is greater than zero. If the content-length is zero then a branch is made to `0x0042a0d4` which in-turn branches again to `0x0042a110`. At `0x0042a110` the address for `SendSoapRespCode` is pushed into `t9`, a static '401' pushed into `a1`, the save registers from the top of `ExecuteSoapAction` are pushed back into save registers from the stack, and `SendSoapRespCode` is called.

![ExeucuteSoapAction-401](/images/ExecuteSoapAction-401.png)

The client receives their response, `net-cgi` exits and everyone is happy.

I am unsure whether this value is verified to be non-zero as part of some sort of 'authentication' of legitimate requests, or due to this value being used in a stream reader later in the thread? Perhaps just to cut down on processing overhead for blank requests; in which case a HTTP 400 may have been more appropriate.

Either way, I shouldn't be able to just ask for the keys to the kingdom and have them given to me.

![PoC-Run](/images/PoC-Run.png)

FIN.