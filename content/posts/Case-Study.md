---
date: '2025-07-25T13:37:10-04:00'
draft: false
title: 'Detecting Internal Domain Collision with Defender for Endpoint'
---
> While onboarding a client to Microsoft Sentinel and MDE, I discovered a subtle misconfiguration involving internal device names leaking to public DNS. This blog breaks down how I found it, the detection logic I used, and how this seemingly harmless mistake could have led to credential theft through a supply-chain vector.

---
## The Setting

A recent project involved onboarding a new client to Microsoft Sentinel. Their tenant and workspace were already configured, along with Defender XDR. My job was to reduce alert fatigue by fine-tuning analytics rules, whitelisting noise (after validating it wasn't malicious), and creating new rules for coverage gaps.

The client had over **1,500 Sentinel incidents** and **900 Defender XDR incidents** in just 90 days, that's over **2,400 total**. That's overwhelming for any SOC and guaranteed SLA breaches.

---

## Step 1: Analyzing the Noise

I started by identifying which rules were firing most. Many of the noisy rules were triggered by devices not following the expected naming convention.

I learned something odd: while the client **does not officially allow BYOD**, they **do** allow users to sign in from unmanaged devices. Once signed in, **Defender for Endpoint (MDE)** gets deployed and begins collecting telemetry.

Even stranger, some employees connect using **partner company devices**, which are part of entirely different environments. It's not great practice, but... business requirements often trump security.

**My first thought?** If you don't allow BYOD, enforce Conditional Access to block unmanaged devices. But I digress.

---

## Step 2: Digging into Internal Domains

This setup got me thinking: could this be a supply-chain risk? I decided to hunt for devices with MDE installed that didn't belong to the corporate domain.

I used the following KQL query to extract internal domain names from device names observed by MDE:

```kql
union Device*
| where Type !in ("DeviceInfo", "DeviceNetworkInfo") // Excluded for accuracy (explained later)
| distinct DeviceName
| extend internalDomain = extract(@"[^.]+\.\w+$", 0, DeviceName)
| summarize count() by internalDomain
```

This revealed:
- Devices from the corporate domain
- Devices from `WorkGroup`
- And one curious case:  
  `device.unexpectedDomain.com`

I checked WHOIS... and the domain was **available for purchase**.

🚨 🚩 **That's a red flag.** 🚩 🚨

I jumped on a call with the client. Their official domain was `.net`, not `.com`. They were shocked and registered the domain immediately.

---

## Why Does This Matter?

You might ask: *“So what if someone uses a real FQDN internally?”*

Here's the risk:

- **Internally**, DNS resolves `dc1.unexpecteddomain.com` to an internal IP.
- But **off-network**, the device tries public DNS resolution.
- If someone **buys that domain and sets up a DNS server**, they'll start receiving DNS requests. By consequence, potentially leaking **service names**, **hostnames**, and even **NTLMv2 authentication attempts.**

**How?** It follows the DNS resolution chain:
- hosts file  
- DNS cache  
- configured DNS server  
- ...and then, if unresolved, it **reaches out to the internet**.

---

## A Real-World Example

This exact scenario was documented in a talk by **Philippe Caturegli** ([Watch it here](https://www.youtube.com/watch?v=Dq0iCgEQNhM)).

In a red team engagement, he noticed a similar internal FQDN available online. He bought the domain, set up a DNS listener, and was flooded with requests from the client's environment, including NTLMv2 authentication attempts.

With some cracking, he recovered credentials, bypassed MFA, and gained VPN access. Go watch the talk if you haven't. It's gold.

---

## Step 3: What About DeviceInfo and DeviceNetworkInfo?

I excluded those tables from the earlier query. Why?

Because **MDE performs subnet discovery** on nearby devices *only* if it considers the environment corporate (e.g., joined to Entra ID or hybrid-joined). This can result in telemetry from **external** or **partner-owned** devices being recorded, even if they aren't onboarded.

So I ran the query again, this time **targeting non-client domains only**.

---

## The Results Were Wild

I found tons of unrelated internal FQDNs. Most were still available for registration.

But one stood out:

```
deviceName.internalDomainCompanyName.AD
```

At first glance, `.AD` looks like a harmless abbreviation for Active Directory.

But in reality, `.AD` is the **country code top-level domain (ccTLD) for Andorra**. \
A country with an active DNS infrastructure.

If someone registered `internalDomainCompanyName.ad`, set up a DNS server, and waited… any misconfigured system trying to resolve `*.internalDomainCompanyName.ad` would leak sensitive DNS traffic.

The client chose not to investigate further, since the devices belonged to external partners. However, this is exactly how **supply-chain risks** begin, when trusted business relationships introduce indirect exposure.

---

## Detection: Unexpected Internal Domains in Device Names

Once you've completed your initial hunting and defined your expected internal domains (or put it in a watchlist), you can use this query as an analytics rule. It runs hourly and flags unexpected domains showing up in `DeviceName` fields across MDE tables.

```kql
let knownInternalDomains = dynamic(["corpdomain.local", "corpdomain.tld"]); // Replace or reference a watchlist if preferred
union Device*
| where TimeGenerated > ago(1h)
| where Type !in ("DeviceInfo", "DeviceNetworkInfo")
| extend internalDomain = tolower(extract(@"[^.]+\.\w+$", 0, DeviceName))
| where isnotempty(internalDomain)
| where internalDomain !endswith ".workgroup"
| where internalDomain !in (knownInternalDomains)
| summarize Devices = make_set(DeviceName), Count = count() by internalDomain
| order by Count desc
```

---

## Lessons Learned

- **Use real TLDs (e.g., `.com`, `.net`, `.ad`, `.ca`) for internal domains only if you own and control the domain.**  
  Even though ICANN recommends using subdomains (e.g., `internal.company.com`), this still carries risk, such as subdomain takeover, DNS leaks, or wildcard certificate abuse. Keep monitoring for dangling or misconfigured records.

- **Usage of non-public like `.local`, `.lan`, or `.internal`**  
  They Eliminate the risks of data leakage but they are not standards-compliant and can break service discovery (mDNS), Kerberos authentication, and TLS certificate issuance in certain environments.

- **Audit internal telemetry regularly to detect leaks of internal FQDNs.**  
  Use MDE, Microsoft Sentinel, DNS logs, or any other relevant telemetry to spot internal names exposed in external traffic, beaconing, or cloud access.

---

## Final Thoughts

This wasn't an elite 0-day. But it's exactly the kind of misconfiguration that's:

- Easy to overlook  
- Exploitable with minimal effort  
- Capable of causing real damage

If you're running Sentinel or MDE, run the query I shared and see what's lurking in your device names.

You might be surprised what's leaking.

**Thanks for reading.**  
Hope this helped you see internal domain names in a new light.