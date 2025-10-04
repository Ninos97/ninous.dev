---
date: '2025-10-04T16:15:00-04:00'
draft: false
title: "From Silent Failures to Reliable Baselines: Sentinel Lookback Limitations Workaround with Summary Rules" 
---

I recently stumbled onto a strange behavior in Microsoft Sentinel while testing a query I had built a few weeks earlier (Check my previous [blog](https://ninous.dev/posts/bec_case_study/)). I had pushed a rule in test mode to observe firing rate and fidelity. Two weeks later, while presenting the query, I ran it over historical data and got a hit. But when I checked the **Incidents** tab, the rule had never triggered.  

What happened?  

---

## The Problem

In my case, I had built a baseline query that looked back **14 days** to map each UPN -> {Set_of_IPs}. The Analytics rule, however, was configured with a **2-day lookback**.  

Here’s what I expected Sentinel to do:  
- If my query says "14 days" but the rule allows only "2 days" it should just **clip** the time range to 2 days. That might cause false positives due to a smaller baseline, but at least the rule would still fire.  
- Or, at minimum, give me a **warning** that my query is asking for more data than the rule allows, so I could fix it on the spot.  

Instead, Sentinel silently failed. My detection ran, but no incident was created.  

And by "silently" I mean I checked **SentinelHealth**, and all other Sentinel-related tables and the only logs I found indicated the rule had run successfully.

---

## What Sentinel *Should* Do

- Warn when a query lookback > rule period  
- Or gracefully adjust the query to the allowed timeframe  

## What Actually Happens

- Query can fail entirely without Sentinel logging the failure in the appropriate tables  
- No incidents are generated  
- No warnings are shown in the Analytics tab when creating rules  

From older discussions in the community, it seems Sentinel *used* to show a [warning](https://techcommunity.microsoft.com/discussions/microsoftsentinel/what-is-leading-query-scheduling-or-the-lookback-in-the-query/1979918) for this scenario, but that behavior has since disappeared. If anyone has recent validation on this, please share.  

---

## Why This Matters

When this occurred, it was worrying because it opened my eyes that **other rules might be silently failing without any way of validating**.  

The first step was to dig manually and ensure every single rule from the in-house **catalog** of detections my clients use didn’t have a mismatch between rule period and in-query timeframe.  

This highlights a dangerous **false sense of security**. I’ve seen multiple blogs mention this: "nothing triggered, so everything’s fine." In reality, rules may be silently failing. That’s just as dangerous as a false negative, maybe even more so if you’re confident in your rules.  

I’ll assume this is a rare scenario, but it raised the bigger question: *how do I get my rule working without requiring large lookback periods while keeping its integrity and fidelity?*  

---

## Workarounds / Solutions

So how do you deal with queries that require longer lookback times?  

### 1. Adjust Rule Frequency
- At **5m frequency**, Sentinel caps lookback at **2 days**.  
- At **1h frequency**, the cap increases to **14 days**.  
- This is the easiest fix if you can live with hourly runs and are satisfied with a 14-day maximum lookback.  

---

### 2. Summary Rules + Custom Tables (_CL)
This is my go-to solution for baselining.  

- Create a Summary rule that stores aggregated data into a custom table (`_CL`).  
- Run it once to create the new table and generate initial entries.  
- Modify the Summary rule to combine new data with the existing table.  
- Then, run your Analytics rule against the summarized table with a shorter lookback.  

This keeps queries fast, cheap, and immune to retention limits.  

**Example (initial baseline):**  
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| summarize make_set(IPAddress) by UserPrincipalName
```

This creates the new table. Let’s call it **SigninLogs_Baseline_CL**.  
Now adjust the Summary rule to merge fresh data with the baseline:  

```kql
let t1 = SigninLogs
| where ResultType == 0
| extend UserPrincipalName = tolower(UserPrincipalName)
| summarize make_set(IPAddress) by UserPrincipalName;
let t2 = SigninLogs_Baseline_CL;
union t1, t2
| summarize set_IPAddress = make_set(set_IPAddress) by UserPrincipalName
```

**Why this works:**  
1. If a user doesn’t sign in, the data is retrieved from `SigninLogs_Baseline_CL`, so nothing is lost.  
2. If the user signs in, the new IP address is added to their existing set of IPs.  

Note: Keep in mind that `set of (set of elements)` -> `set of elements`. This is why the logic holds.  

---

### 3. Watchlists

If you don’t want to use a summary table:  

- Good for smaller reference datasets (≤10k rows).  
- The challenge is keeping them updated automatically.  

Options for automation:  
- **Logic Apps**: schedule a query -> export results -> update the watchlist daily/hourly.  
- **Notebooks**: more flexible, especially if you need preprocessing.  

Once automated, this becomes low-maintenance.  

---

### 4. External API Push (advanced)

While I’ve never implemented this myself, the idea seems feasible with some tinkering:  

- Use the **Log Analytics API** to run resource-intensive queries outside Sentinel’s Analytics rules.  
- Push results back in as incidents or reference tables.  

Caveats: API throttling, rate limits, and more moving parts. I haven’t seen this used in production, but technically it’s possible.  

Note: It’s unclear if the new unified SecOps portal in Defender has an API for creating incidents directly, as Azure Sentinel connectors do.  

---

## Cost Considerations

While I don’t expect Summary rules to create significant costs, it’s always smart to validate. Run your summary query in Log Analytics with a larger time range, bin results by 1d (or your chosen frequency), and use the `_BilledSize` field to estimate. Then calculate costs for your environment.  

Example:  

```kql
let pricePerGb = 4.3; // Adjust to your cost per GB
union *_CL
| where TimeGenerated > ago(30d)
| where _IsBillable == true
| summarize BilledSizeBytes = sum(_BilledSize) by Type //,bin(TimeGenerated, 1d)
| extend BilledSizeGB = BilledSizeBytes / pow(1024, 3) //From Bytes to GB divide by 1billion~
| extend DailyCost = round(pricePerGb * BilledSizeGB, 3)
```

---

## Key Takeaways

- Watch for mismatches between rule period and query lookback.  
- Sentinel can, in rare cases, fail to log rule failures.  
- Summary rules are a reliable workaround for building large baselines in Analytics rules.  

---

Thank you for reading. I hope you found value in my experience.
If you’ve run into similar issues and handled them differently, please share them with me!