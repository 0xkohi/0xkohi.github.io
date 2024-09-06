---
author:
  name: "kohi"
date: 2024-08-09
linktitle: CTI Discord bot
type:
- post
- posts
title: CTI Discord bot
weight: 2
series:
- Tools
---

## Context

I decided to create a Discord bot that could be useful, for me and maybe for some people. The bot has many use cases, on my side I will use it in malware analysis and has
a threat intelligence news.
Since I am often using discord, using this bot is also a faster way to get the information I need.

## Bot Features

The bot currently has 4 features, more might be added in the future if I get other ideas.
There are three commands available and an automatic news channel.

The commands of this bot are executable with the "/" prefix as follow
![image](/images/bot1.png)

### Group lookup

Starting with the group lookup feature, this command allows you to enter an attacker group as parameter:
![image](/images/bot2.png)

The group entered by the user will ask the json base of ransomwatch telemetry and send the output regarding if it exists or not.
The output contains the name, fqdn, the last time it has been updated:
![image](/images/bot3.png)

### Ip Fraud risk

This feature allows you to enter an IP as parameter:
![image](/images/bot4.png)

The IP address entered will be looked up with the Scamalytics Fraud risk API and send the following output, containing a risk score, a link to get more details and the overall risk level:
![image](/images/bot5.png)

The link redirects you to the webpage of Scamalytics with a more detailed analysis, on which you can find the operator and the geographical location.
![image](/images/bot6.png)

### Sample check

The Sample check features basically tells you all the information of the malware sample's hash that you entered as parameter.
![image](/images/bot7.png)

It queries the MalwareBazaar's database and the output contains the following information:
![image](/images/bot8.png)
![image](/images/bot9.png)

### News

This last feature requires you to precise a channelId in which the bot will send every new post of the telemetry watch json base: https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json 

The scheduler is checking every hour if there is a new post, since it's not always the case it is possible that nothing happens times to times.

## Features to be added

- Crawling other websites to add more news/hour
- ...

## Using the bot

The bot is not yet avaible on the Discord App Directory (working on it). If you want to use it beforehand feel free to contact me.
