---
title: "Case Study: When Defender Misread a Windows Upgrade as Ransomware"
date: "2025-10-26T00:00:00-04:00"
draft: false
---

## Disclaimer
> All data and screenshots are fully anonymized and used for educational purposes only.

## Summary
> A Windows 11 upgrade, a dormant Gootloader ZIP, and Defender’s behavioral correlation logic. A mix that led to one of the most interesting false positives I’ve seen. 
> 
> This case-study walks through how Defender pieced together legitimate upgrade activity into a multi-stage ransomware incident, and what it says about context in detection engineering.


## Story Time
Recently, I worked on a multi-stage incident where the final stage turned out to be ransomware. Here’s how it unfolded.
First things first: **isolate**, then investigate.

![](/assets/images/ransomware-incident/1.png)

The case was classified as multi-stage, meaning several detections rolled into a single incident. This one had four parts.

The first alert, *“Suspicious service launched,”* immediately caught my attention. Those always make me uneasy because they *can* indicate long-term persistence finally executing after a period of silence. If that were true, it could’ve been sitting quietly across multiple endpoints. (Interestingly, another device triggered a different multi-stage in the same hour with the same first three components, but the last one was labeled *“info-stealer.”* Side note: weird to have an info-stealer as a **service**, right?)

The second alert, *“Suspicious hardware discovery,”* didn’t concern me much. In my experience, those are rarely true positives. (Though, part of me kind of wants to see one… just without dealing with the aftermath, obviously.)

Then came the third: *“Anomaly detected in ASEP registry.”*
If you’re not familiar, **ASEP** stands for **Auto Start Entry Point** (or **Auto-Start Extensibility Point**, depending on which doc you read). These registry keys let binaries execute automatically. Typically at boot. In simpler terms, it’s persistence through the registry.

And finally, the big one, the so-called *ransomware*.

![](/assets/images/ransomware-incident/2.png)

`svchost.exe` the usual. Nothing special happening here.

![](/assets/images/ransomware-incident/3.png)
![](/assets/images/ransomware-incident/4.png)

A quick Google search confirmed that **TSManager.exe** is part of SCCM, responsible for handling task sequences during deployments and updates. I also double-checked the **LOLBAS** project just in case it was one of those dual-use binaries that could be abused by attackers, it wasn’t.

![](/assets/images/ransomware-incident/5.png)

Even the **WMI** queries looked completely normal. At that point, I wasn’t really following Microsoft’s logic for flagging this chain.

![](/assets/images/ransomware-incident/6.png)

Then I noticed a few binaries I didn’t immediately recognize. Based on their names, though, they looked like OS upgrade components, nothing out of the ordinary. Still, I had to be sure. **OSDUpgradeOS.exe** and **OSDPrestartCheck.exe** were both signed by Microsoft, and VirusTotal confirmed they were legitimate. So far, the story checked out.

Next up was **setup.exe**, running with a rather long command line:

![](/assets/images/ransomware-incident/7.png)

> **EULA** = End User License Agreement  
> **NoReboot** = No reboot after completion  
> **PostOOBE** = Post Out-Of-Box Experience

There were also two CMD scripts for post-upgrade or rollback operations. Once again, perfectly normal behavior for an in-place Windows upgrade. I validated both using `Invoke FileProfile` on their hashes, they were common across multiple environments.

![](/assets/images/ransomware-incident/8.png)

The trail continued with more setup activity, I don't see anything suspicious yet.

![](/assets/images/ransomware-incident/9.png)

Then came the next sequence of processes. I wasn’t familiar with the path at first, so I Googled it. Turns out, it’s one Windows uses temporarily during upgrades. So again, routine behavior.

More benign processes here and there, nothing special.

![](/assets/images/ransomware-incident/10.png)

As I went further down the timeline, I kept seeing more system processes behaving exactly as expected. At this point, I had no clue why I was looking at what Defender labeled a ransomware incident.

![](/assets/images/ransomware-incident/11.png)
![](/assets/images/ransomware-incident/12.png)
![](/assets/images/ransomware-incident/13.png)

Then something new caught my eye: a set of records named `$OFFLINE_RE_HEX(Sid)`.

Googling didn’t help much, so I resorted to ChatGPT for context (please don’t judge me). Here’s what I learned:

`HKEY_CURRENT_USER` (**HKCU**) isn’t a standalone hive, it’s a pointer to the user’s `ntuser.dat` file stored under `C:\Users\<username>\ntuser.dat`. When a user logs in, Windows loads that hive into memory.

It seems MDE monitors for changes involving `ntuser.dat`, which makes perfect sense since it’s a common persistence target. In this case, though, there weren’t any malicious modifications. My theory is that the Windows upgrade process copied these profile files from their original paths to a temporary staging directory. Because MDE keeps a close eye on sensitive files, it flagged these copy operations as registry anomalies affecting HKCU.

And since the user wasn’t logged in during the upgrade, MDE labeled those entries as `offline_rw_HEX`, meaning modifications to offline user hives.

If anyone reading this has a better explanation, feel free to correct me, always happy to learn.

I went through each of those offline entries, and every single one showed benign activity: Teams updating, OneDrive starting, and other routine background tasks.

Once again, everything looked normal. Expected behavior. Definitely not ransomware.

![](/assets/images/ransomware-incident/14.png)

Next up was **smstsmgr.exe**: a quick Google search confirmed it’s yet another legitimate Windows component.

And then, finally, things started to get interesting, the so-called *“ransomware.”*

![](/assets/images/ransomware-incident/15.png)
![](/assets/images/ransomware-incident/16.png)
![](/assets/images/ransomware-incident/17.png)

Oh, did I mention I love **MOTW** (Mark-of-the-Web)? Because I do.

![](/assets/images/ransomware-incident/18.png)

Now things were finally starting to make sense… but there were still a few caveats.

How did this file even end up on the device? It was clearly sitting in the **Downloads** folder, but why hadn’t it triggered anything before? Was it ever executed?

Based on the indicators of compromise, I could make an educated guess: this looked like **Gootloader**. The filename structure gave it away. It followed the same pattern as a previous Gootloader case I investigated back in early 2023:

`word1_word2_word3_..._number.zip`

![](/assets/images/ransomware-incident/19.png)

That path told me everything: the file had been copied to `NewOS\Users\<username>\Downloads` during the Windows upgrade process.

When MDE triggered the incident, the malware wasn’t running at all. It had simply been sitting there, dormant, for quite some time. Over a year, in fact.

What didn’t make sense was why Defender treated this as a **multi-stage ransomware** event when the only malicious element was an old ZIP file quietly sitting on disk. Why now? Why label it as active ransomware?

Well… here’s why:

![](/assets/images/ransomware-incident/20.png)

And there it was, the smoking gun.

The process that “created” the malicious ZIP file? **setupHost.exe.**

From earlier, we already knew it’s a legitimate Windows component used during upgrades. The logs showed that setupHost.exe modified over **5,000 files**, which simply meant it was copying user data, including the **Downloads** folder, to the staging directory for the Windows 10 → 11 upgrade.

So why didn’t this trigger before? Simple: the device never had a **Full Scan**.

The client had deployed MDE but skipped the post-onboarding full scan. The malicious ZIP had been sitting there long before Defender ever showed up. Since no process interacted with it, MDE didn’t know it existed until setupHost.exe copied it, and that single action checked all the boxes for ransomware behavior:
**High count of file modifications + MOTW correlation + known CTI of Gootloader abused domain**.

Thankfully, this one turned out to be a **false positive in context**. The file itself was indeed malicious, but it wasn’t active. Defender flagged it only because the upgrade process interacted with an old artifact that had been sitting there for over a year.

Still, it was a fascinating case, a reminder of how Defender stitches together behavioral data to tell a story, even when that story doesn’t quite fit the facts.

False positives like this are gold. They reveal how the black box thinks, how detections correlate, and where logic can overreach. Every one of them teaches us something new.

---

## Lessons Learned

This case was a solid reminder that **Defender’s behavioral correlation is powerful, but context matters**.

When onboarding endpoints, always run a **Full Scan** to surface dormant threats before they reappear during legitimate processes.

It also highlighted how Defender leverages **MOTW** and file modification patterns to identify ransomware activity. Even legitimate processes can look malicious when context is missing.

---

## Key Takeaways
- Not every ransomware detection means active ransomware.
- Always perform a **Full Scan** post-onboarding.
- Windows upgrades can trigger false positives when old malware resurface, even if it isn’t running because legitimate processes can still interact with malicious files..
- Understanding Defender’s behavioral logic helps separate real threats from misinterpreted activity.

---

## References
(1) https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts  
(2) https://app.tidalcyber.com/capability/0bbc5707-1fc2-52a4-86cc-d05bec4a518f

This one turned out to be a false positive, but a pretty interesting one. The best part? It taught me more about how MDE’s internal logic connects seemingly unrelated signals into a coherent story, even when that story occasionally needs a fact-check.