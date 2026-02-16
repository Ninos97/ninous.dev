---
title: "Identifying Unusual User-Agents: a Hands-On Hunt"
date: "2026-02-13T23:00:00-04:00"
draft: false
---

## Disclaimer
> I usually use ChatGPT to format and rewrite the text for a better structure. For this post, I decided to do it without the usage of any LLM.    

## Personal updates
It has been a while since I posted anything new. I've been quiet busy last couple of months. I traveled to Zurich to attend **KustoCon**, it was amazing. I kinda wish there was a similar event in Montreal. Maybe one day.

I switched jobs! I left the MSSP I was working for, for the last three and a half years and started working as a consultant at a Canadian crown corporation. It took some time to get back to the blogs. Here I am, that is what's new with me.

## Back to work: 
Before starting the blog, I had a few ideas I wanted to do research on and write about but one topic I didn't think I'd write about is *user-agents*. I considered it to be not worth the time since user-agents are easily changed. It's trivial but I've seen it remain unchanged more than I can count in lots of investigations. When we talk about phishing, we mostly talk about AiTM incidents that show up in Defender as high severity. In these investigations, countless times I've seen "Axios". A simple google search will explain what that user-agent is.   

## Known malicious User-Agents: 
There is a plethora of resources to find malicious user-agents, we can find them through Threat Intel reports, github repos and maybe even blogs.  
I don't like the idea of having a pre-determined list of what is considered malicious or not. Because if we are running the list against observed user-agents in the environment, we're doing an `==` basically, so any change in the user agent will make it obselete. A simple change such as different version, adding a space, or some other addition. All of these will give us the false impression that no malicious user-agents are present.  

## What to do then?
Since the approach of a static list is off the table, we have to analyze what we see in our environment without having to go through every single user-agent.  
I want to find anomalies. That's the idea, but how?

What I want to do is break down each user-agent into keywords, clean up the versions, filter out noise and then get stats based on the occurrences of each word in number of unique user-agents, the number of signins per-keyword, as well as other stats which can be added later on (Number of unique users, appsDisplayName etc.)

### 1. Gather all unique user-agents:
```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0 //Only Successful signins
| summarize count_ = count() by UserAgent
```
> **Side note:** (Don't sleep on non-interactive signins).  

### 2. Breaking down user-agents:
I started initially with some basic splitting based on `\w+`, `[^\s]+` and some other variants.  
After multiple iterations and understanding better what i'm working with, I reached this:
```kql
| extend Keywords = extract_all(@"(?i)(https?[^\s]+|\WNET[A-Za-z0-9\.]+|Mobile|\w+(?:(\-|=|\.)\w+)*)", tolower(UserAgent))
```

I saw some repetitive and noisy User-Agents where there are many variants so I filtered those out.  
Did some regex_replace to clean up some versioning. 
```kql
| extend UserAgent = replace_string(UserAgent, "%20", " ") //Sometimes this url decoding is needed
| extend UserAgent = replace_regex(UserAgent, @"\/([A-F0-9\.]|[Vv]\d+)[^\s]+", "") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Linux; Android [^\)]+\)", "(Linux; Android)") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Macintosh;[^\)]+\)", "(Macintosh)") //Can remove more data than expected. Validate manually
```
```kql
| where UserAgent !startswith "Dalvik"
| where UserAgent !startswith "MSAL"
| where UserAgent !startswith "CredentialProvider.Microsoft"
| where UserAgent !startswith "Microsoft Authenticator"
```

Filtering some noisy output from the regex:
I used mv-apply on keywords -> initially had a more developed logic but can probably just remove it if no additional filering is happening
```kql
    where Keyword matches regex "[A-Za-z]"
    | summarize clearedKW = make_set(Keyword)
```

Putting it together:
```kql 
let lookback = 999d;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| summarize count_ = count() by UserAgent
| extend UserAgent = replace_string(UserAgent, "%20", " ") //Sometimes this url decoding is needed
| extend UserAgent = replace_regex(UserAgent, @"\/([A-F0-9\.]|[Vv]\d+)[^\s]+", "") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Linux; Android [^\)]+\)", "(Linux; Android)") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Macintosh;[^\)]+\)", "(Macintosh)") //Can remove more data than expected. Validate manually
| summarize TotalCount = sum(count_) by UserAgent
| where UserAgent !startswith "Dalvik"
| where UserAgent !startswith "MSAL"
| where UserAgent !startswith "CredentialProvider.Microsoft"
| where UserAgent !startswith "Microsoft Authenticator"
| extend Keywords = extract_all(@"(?i)(https?[^\s]+|\WNET[A-Za-z0-9\.]+|Mobile|\w+(?:(\-|=|\.)\w+)*)", tolower(UserAgent))
| mv-apply Keyword = Keywords on (
    where Keyword matches regex "[A-Za-z]"
    | summarize clearedKW = make_set(Keyword)
    )
| summarize clearedKW = make_set(clearedKW)
```

### 3. Understanding the environment:
Now we have the set of words. If you run this in your environment, I recommend taking a look at the results here to find immediate weird keywords.  
you might notice some patterns of elements to filter out, or regex enhancements.  
There's a room for improvement on this end, for my specific needs it works pretty well. You will need to tinker quiet a bit depending on what your results.

Next, we want to count the occurrence of each of these words from unique user-agents. We're still in the "hunting" part of building the end-query. We want to find rare keywords and understand why they exist in our environment.

### 4. Getting stats:
I mentioned initially I'd like to get an understanding of my environment and the user-agents' keywords existence and occurrences. If you see the last line in the query, i'm summarizing all keywords in a single set and that is the output of my query.  
I will need ot join this to another dataset which is, once again, union SigninLogs, AADNonInteractiveUserSignInLogs.

I did the classic workaround of extending a joinKey, just to be able to have it in the same row as my user-agents.
Here's my query:
```kql
let lookback = 999d;
let t1 = materialize (union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| summarize count_ = count() by UserAgent
| extend UserAgent = replace_string(UserAgent, "%20", " ") //Sometimes this url decoding is needed
| extend UserAgent = replace_regex(UserAgent, @"\/([A-F0-9\.]|[Vv]\d+)[^\s]+", "") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Linux; Android [^\)]+\)", "(Linux; Android)") //Can remove more data than expected. Validate manually
| extend UserAgent = replace_regex(UserAgent, @"\(Macintosh;[^\)]+\)", "(Macintosh)") //Can remove more data than expected. Validate manually
| summarize TotalCount = sum(count_) by UserAgent
| where UserAgent !startswith "Dalvik"
| where UserAgent !startswith "MSAL"
| where UserAgent !startswith "CredentialProvider.Microsoft"
| where UserAgent !startswith "Microsoft Authenticator"
| extend Keywords = extract_all(@"(?i)(https?[^\s]+|\WNET[A-Za-z0-9\.]+|Mobile|\w+(?:(\-|=|\.)\w+)*)", tolower(UserAgent))
| mv-apply Keyword = Keywords on (
    where Keyword matches regex "[A-Za-z]" // should be removed since we filter out based on strlen later on
    | summarize clearedKW = make_set(Keyword)
    )
| summarize clearedKW = make_set(clearedKW) | extend joinKey = 1);
t1
| lookup kind=inner (union SigninLogs, AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(lookback) | where ResultType == 0 | summarize count() by UserAgent | extend joinKey = 1) on joinKey
| mv-expand Keyword = clearedKW to typeof(string)
| where strlen(Keyword) > 1 //Filters out single character extracts
| summarize SumOfLoginsPerUserAgentKeyword = sumif(count_, UserAgent has Keyword), NumberOfUserAgentsContainingKeyword = countif(UserAgent has Keyword), sampleUserAgents = make_set(iff(UserAgent has Keyword, UserAgent, ""), 10) by Keyword
| where SumOfLoginsPerUserAgentKeyword > 0 and NumberOfUserAgentsContainingKeyword > 0 //Due to the filtering applied on the initial user-agent to remove some UAs containing some keywords
```

### 5. Performing Investigations & Fine-Tuning:
I mentioned it and I'll repeat it again. Every environment is different, my regex and filters work for my needs, they will not work for all environments. This is where detection specialists come in and enhance the query to fit their organization's needs.

There are ways to enhance the query and have it add additional stats and context like number of users, apps, locations etc.
I wont do it in this blog, let this be an exercise.

---
## Closing notes:
This blog went through multiple iterations and I basically had to rewrite it because my initial approach was not solid in a production environment.  
I had some queries that were very heavy in terms of resources and sentinel engine would not run them. The most it could handle was a few hours of lookback time, which is obviously terrible. So I had to rewrite it form scratch.

This is my first blog since starting at my new place of work, one of the downsides of no longer working for an MSSP is that I cannot run such queries against 10s of environments and adjust the queries to be a better fit for the general population and learn about edge-cases. But, on the other hand, I don't need to account anymore for ALL kinds of environments which makes my life easier.

This has been fun, hope you found value here.
Thank you for your time.

---