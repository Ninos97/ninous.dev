---
date: '2025-09-06T18:52:10-04:00'
draft: false
title: 'When Trusted Senders Become Threats: A BEC Case Study in Microsoft 365'
---

Recently I received a ticket to create a detection for a client BEC. Microsoft Defender for Office 365 (MDO) didn't flag the phishing email, but Entra ID raised **Unfamiliar sign-in properties** and the incident surfaced in Sentinel.

## Storytime: the signals we saw

- Sentinel incident: **unfamiliar sign-in properties**; RiskEventType: "unfamiliarFeatures" and "passwordSpray".
- Indicators: **User-Agent `axios/1.11.0`**, sign-in source: **M247-LTD Los Angeles Infrastructure** (`m247global.com`); Classic hosting/DC footprint.
- Conditional Access forced MFA; logs confirm **MFA was passed**.
- The client confirmed compromise. The user was not using VPN or any odd third-party apps.

I pivoted to URL clicks around the time of the malicious sign-in. In **UrlClickEvents** for the victim over the prior few minutes to hours, most URLs looked normal, but one stood out. Sandboxing showed a **"file was shared -> enter email"** lure that then **redirected to a newly registered `.ru`** page impersonating Microsoft 365.

### Why didn't MDO catch it?

Three factors made this nasty:

1. **Compromised business domain** hosted the initial page. It was aged (~6 years), no bad VT hits yet, so reputation looked fine.  
2. **Email came from a known, trusted external sender** (their account was also compromised).  
3. **The phishing flow used a stager page:** Instead of showing a fake login immediately, every link on the landing page redirected to the same anchor (`#`) and opened a sliding window asking for an email. Only after entering an email did it redirect the user to the real credential-harvesting `.ru` page. This extra indirection made the lure appear more legitimate and harder to detect compared to standard phishing pages.  

MDO's anti-phishing stack uses multiple signals, including **mailbox intelligence** (sender/recipient relationship history) and **impersonation/spoof protections**. That legitimate relationship and infrastructure can **lower scrutiny**.

In short: **trusted sender + aged domain + novel redirect** can slip past initial filters until indicators catch up.

## MDO Stack
![Microsoft MDO stack](https://learn.microsoft.com/en-us/defender-office-365/media/mdo-filtering-stack/mdo-filter-stack-phase5.png)

## The detection idea

The idea is to connect multiple weak signals into a higher-confidence detection:  

1) User clicks a link (UrlClickEvents).  
2) Within a short window, the same user has their **first observed sign-in from a new IP** (SigninLogs).  
3) If Entra ID raises risk related to this new IP, confidence increases significantly.  

This type of correlation is designed to surface **phish -> credential use -> risky login** patterns quickly.  

### KQL (v0.1)

```kusto
// Parameters
let LookbackWindow = 1h;            // Lookback for clicks & sign-ins
let RiskWindow     = 1h;            // Window to search for user risk signals
let MaxMinutesClickToSignin = 5;    // Window between URL click & Suspicious Sign-in
let BaselineTimeData = 14d;         // Safe IPs per user lookback time
// Assumed safe IPs per user
let HistoricalSafeIPs = 
	SigninLogs
	| where TimeGenerated between (ago(BaselineTimeData) .. ago(2h))
    | where ResultType == 0
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | summarize make_set(IPAddress) by UserPrincipalName;
// Clicks in the last hour
UrlClickEvents
| where TimeGenerated > ago(LookbackWindow)
| extend URLClickTime = TimeGenerated
| extend UserPrincipalName = tolower(AccountUpn)
| project URLClickTime, UserPrincipalName, Url, UrlChain
| join kind=inner (SigninLogs
    | where TimeGenerated > ago(LookbackWindow)
    | extend SigninTime = TimeGenerated
    // We want the FIRST instance of the user-IP combo since it will be the closest to the URL click event we want to capture -> arg_min
    | summarize arg_min(TimeGenerated, *) by IPAddress, tolower(UserPrincipalName)
    | project
        SigninTime,
        UserPrincipalName,
        IPAddress,
        PostClickResultType = ResultType,
        UserAgent)
    on UserPrincipalName
| extend MinutesClickToSignin = datetime_diff('minute', SigninTime, URLClickTime)
| join kind=leftouter HistoricalSafeIPs on UserPrincipalName 
| where not(set_has_element(set_IPAddress, IPAddress)) or isempty(set_IPAddress)
| where MinutesClickToSignin between (0 .. MaxMinutesClickToSignin) // 5 minutes 
//At the moment we're using kind=inner; we might want to use leftouter in future versions when we create our own risk detection signals
| join kind=inner (AADUserRiskEvents
    | where TimeGenerated > ago(RiskWindow)
    | extend RiskySigninTime = TimeGenerated
    | extend UserPrincipalName = tolower(UserPrincipalName))
    on UserPrincipalName, $left.IPAddress == $right.IpAddress // We want risk to be related to the new IP
| extend MinutesClickToRisk = datetime_diff('minute', RiskySigninTime, URLClickTime)
| where MinutesClickToRisk between (0 .. 60) // 1h
```

**Notes**
- **UrlClickEvents** is a Defender for Office 365 data source. Ensure it's enabled and configured properly.
- **AADUserRiskEvents** is emitted by Entra ID Protection and contains user risk detections (e.g., unfamiliar sign-in properties).  
- `tolower()` normalization is applied consistently across joins to avoid mismatches.  
- The logic focuses on **new IPs** (not in the user's historical safe set) that occur shortly after a URL click.  

## Assumptions

1) MDO is in use; **UrlClickEvents** is populated.  
2) Users click links directly (no QR/manual copy) so clicks are recorded.  
3) Users typically submit credentials within ~5 minutes of clicking. Adjust `MaxMinutesClickToSignin` if needed.  
4) Entra ID Protection is enabled and populating **AADUserRiskEvents**. 
5) Risk signals can **arrive with delay**; we allow up to 60 minutes from click to risk.  

## Why this works (and where it can fail)

- **Strength:** Correlation across independent signals (click, new IP, risk) increases detection fidelity.  
- **Noise control:** Baseline of safe IPs reduces false positives from known user behavior.  
- **Mobile/IPv6:** This is the main FP vector. Consider tuning for mobile-specific user-agents or perhaps implementing exclusion of mobile ISP ASNs vs IPs. Varies from one environment to the other.
- **Latency:** Risk detection isn't immediate; adjust the `RiskWindow` and `MinutesClickToRisk` if misses occur.  

## Future Enhancements

This rule is **v0.1**. It catches the essentials, but there's more to explore:  

- **Per-user baselines:**  
  Functions to track new ASN, user-agent, and location (country + city) over ~90 days. Any deviation from baseline = anomaly.  

- **Org-wide baselines:**  
  Instead of just per-user, look at environment-wide distributions of ASNs and ISPs. Flag outliers relative to peers.  

- **Watchlists for enrichment:**  
  Import ASN -> ISP mappings (from GitHub or local datasets) into Sentinel watchlists. Helps distinguish "Expected ASNs" from genuine anomalies.  

- **Notebook-based anomaly scoring:**  
  Use notebooks to move beyond thresholds into scoring. For example, calculate "distance from baseline" to weight anomalies rather than firing binary detections.  

These approaches are still R&D, but they show where detection engineering can evolve: from **rule-based correlation** to **adaptive anomaly detection** that scales with environment complexity.

## MITRE ATT&CK mapping

- **T1566.002** Phishing: Spearphishing Link  
- **T1078** Valid Accounts  
- **TA0006** Credential Access (MFA interception)

## Closing

Tools miss things. That's reality. Your job as a detection engineer is to **cross-validate weak signals** across products. In this case, **UrlClickEvents + first-time IP sign-in + Entra ID risk** gave us high confidence without waiting for a single product verdict.
