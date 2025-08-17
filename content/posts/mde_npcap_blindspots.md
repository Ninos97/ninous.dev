---
date: '2025-08-16T15:15:00-04:00'
draft: false
title: "Hiding in Plain Sight: MDE's Network Telemetry Blindspots" 
---

## Intro
Earlier this year on LinkedIn, I shared a quirky "feature" in Microsoft Defender for Endpoint (MDE): it happily accepts input from the user as trusted without any validation.  
[(LinkedIn Post)](https://www.linkedin.com/feed/update/urn:li:activity:7317305441527422976/).  

Example:

```bash
curl.exe 142.250.69.142 -H "host: example.com" #One of Google's IPs
```

In MDE, the `RemoteUrl` field will log *example.com*, not the actual destination domain behind the IP.  
Not an exploit, but a perfect way to hide malicious traffic under the "safe domains" umbrella. If your hunting queries filter out common benign sites, you'll miss it entirely.

Why does this happen? Because of how DNS works:

- A single IP can host many domains (CDNs).  
- A single domain can resolve to many IPs (load balancing).  

This makes validation impractical. That's the beauty of abusing design and architecture: sometimes it *can't* be "fixed" like a typical exploit.

That small test got me thinking: **what else could I make Defender misinterpret... or completely ignore?**

---

## Phase 1: Chasing Weird Protocols
When I reviewed `DeviceNetworkEvents` in MDE, I noticed something:  
protocol values were almost always **TCP**, **UDP**, or **ICMP**.

But networking supports far more: **GRE**, **BGP**, **SCTP**, and others rarely seen outside ISP or backbone operations. Just because they're niche doesn't mean they can't be abused.  

The obvious question: *if I send traffic over uncommon protocols, will MDE see it?*

---

## Phase 2: The Raw Socket Roadblock
My first idea was to craft my own packets. But since Windows XP SP2 (2004), Microsoft crippled raw sockets after malware authors abused them [(reference)](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).  
You can't just fire arbitrary packets from userland (Ring 3) anymore.

The workaround? **NPcap** which is the modern, signed replacement for WinPcap.  
It's everywhere: Wireshark, Nmap, and many other tools use it. It runs on Windows 10/11 without raising alarms and lets you send any packet you want.

**Why?**  
Windows blocks raw sockets at the driver level. Drivers make syscalls (Ring 0) that perform physical I/O operations, and userland apps aren't allowed to invoke those directly. NPcap provides a trusted driver that exposes this functionality.

---

## Phase 3: Testing in the Lab
**Setup:**  
- VM: Windows 11 Enterprise with MDE onboarded  
- Tooling: NPcap + minimal Python PoC to send arbitrary packets  
- Observer: Wireshark on host OS  

### Test: Exotic Protocols
I used NPcap to send packets with protocol numbers MDE doesn't normally log (because they shouldn't be there in the first place): GRE, BGP, SCTP.  

**Result:**  
- **Wireshark on host:** captured everything.  
- **MDE:** captured nothing. Interesting.  

When I tried sending those packets to a DigitalOcean droplet, nothing arrived. After debugging and asking some network experts, I learned the packets were dropped somewhere along the path (Firewall -> Router -> ISP -> Backbone -> Cloud Provider).  

Basically, they don't usually make it to the internet, which makes them less useful for real-world C2, but still interesting.

---

## Phase 4: Testing TCP/UDP Packets with NPcap

### UDP: Fully Invisible
- UDP traffic was completely invisible to MDE, **except on port 53**, where it showed the actionType `DnsConnectionInspected`.  
- Additional tests confirmed the same behavior using Windows-native DLLs, so this isn't just an NPcap quirk.  

After more digging (and Googling), I found a few buried mentions in other blogs casually noting that *"MDE doesn't inspect UDP like it does with TCP"* as if this wasn't a huge blindspot.  

I started reviewing C2 frameworks that use UDP, and unsurprisingly, there are plenty of open-source options out there. I've been working with Defender for years, and only discovered this blindspot through deliberate lab testing. This kind of knowledge shouldn't require independent researchers to dig into black-box behavior just to understand what telemetry an EDR actually provides.  

Over the past two weeks of testing, reading, and validating, I've come away with one big takeaway: **we put far too much trust in products that have major visibility gaps.**

---

### TCP: Partially Invisible
- Using Scapy/NPcap to send raw TCP packets, the **first part of the 3-way handshake (SYN)** was invisible to MDE.  
- When the **SYN-ACK** returned, MDE logged it as `ConnectionAcknowledged` but without any process correlation.  

In other words, MDE sees the IP, but has no idea which process initiated the connection.

---

## Phase 5: Why This Matters
If attackers can send traffic that MDE never logs while still allowing normal telemetry, blue teams lose the ability to:
- Correlate endpoint and firewall logs  
- Detect beaconing patterns  
- Understand the true scope of malicious activities  

---

## Phase 6: Detection Opportunities
No silver bullet, but a few starting points:

### 1. Monitor NPcap DLL Loads
```kql
DeviceImageLoadEvents
| where ActionType == "ImageLoaded"
| where FileName in~ ("packet.dll", "wpcap.dll")
```
Tune to your environment: NPcap on a network admin's box may be normal. On HR's laptop? Red flag.

---

### 2. Correlate TCP Oddities
Look for `ConnectionAcknowledged` events without matching `ConnectionSuccess` events for the same IP on the same device.  
Likely high-FP, better suited for hunts than analytical rules.

---

### 3. Cross-Reference Firewall Logs
Compare firewall traffic against `DeviceNetworkEvents` to spot gaps in endpoint telemetry.  

- **UDP:** Look for non-DNS traffic. Validate outbound volume, ports, and destinations.  
  Be sure to account for expected noise such as VoIP or video call traffic.  

- **TCP:** Hunt for flows that appear in firewall logs but are missing in MDE.  
  These discrepancies may highlight traffic that bypassed MDE's visibility.

Keep in mind: for remote users working from home, firewall visibility may not exist unless, VPN without split-tunneling is enforced.

---

# Conclusion
EDRs have blindspots, sometimes major ones. It's easy to assume an EDR solution provides full endpoint visibility, but that assumption is risky. EDR alone is not sufficient; you need additional controls and complementary data sources such as NDRs.  

This research demonstrates that:
- **TCP:** You can create partial invisibility in MDE network logs using NPcap.  
- **UDP:** By default, MDE does not capture UDP traffic, except for DNS-related activity.  
- **NPcap usage:** Blue teams should baseline NPcap activity and investigate anomalies, since it's also leveraged by offensive tools like *EDRSniper*.  
- **Correlation:** Defenders must correlate endpoint telemetry with independent network sensors to close visibility gaps.  

---

## Addition: OS-Level Notes

While testing, I established a TCP connection between my lab box and a Linux droplet.
One interesting rabbit hole I went down: `netstat` also failed to display these "invisible" connections, even when run as Administrator.

This behavior ties back to **ETW (Event Tracing for Windows)**. ETW operates on a pub/sub model where tools like Event Viewer, Sysmon, and EDRs subscribe to published events. However, not all drivers publish to ETW, and NPcap doesn’t.

Windows does include its own packet capture driver (`NDIS-PacketCapture`), which *would* capture all raw packets. The catch: it’s disabled by default due to the high performance overhead, and is generally used for short-term troubleshooting rather than continuous monitoring.

---

## References:
https://hybridbrothers.com/mdi-nnr-health/
https://medium.com/%40cybureauocracy/mdes-devicenetworkevents-table-part-2-connection-actiontypes-1c5ee20d2fc4

---

## Thank You
Thanks for reading. This research was performed on Windows 11 Enterprise running MDE P2, all on default settings.  
This blog is based on my observations, experience, and some educated speculation. If you find flaws in my logic or if I missed something, let me know!