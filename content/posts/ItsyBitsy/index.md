---
author: "Shebu"
title: "ItsyBitsy - THM"
date: "2023-07-23"
tags: ["Elastic", "Kibana", "C2 server"]
cover:
    image: "null"
    # can also paste direct link from external site
    # ex. https://i.ibb.co/K0HVPBd/paper-mod-profilemode.png
    alt: "<alt text>"
    caption: "<text>"
    relative: false # To use relative path for cover image, used in hugo Page-bundles
---


**ItsyBitsy** is a medium difficulty room from tryhackme which involves using Kibana  to examine the network connection logs of a suspicious user, find the link and the content of the file, and answer the questions.

![1](img/itsybitsy.png#center)


|  **Room** 	| ItsyBitsy          	|
|:--------------:	|----------------------------------------------------	|
| **Difficulty** 	| Medium                                             	|
|  **Room Link** 	| [https://tryhackme.com/room/itsybitsy](https://tryhackme.com/room/itsybitsy)               	|
|   **Creator**  	| [Dex01](https://tryhackme.com/p/Dex01) 	|




## Task 1 : Introduction

In this challenge room, we will take a simple challenge to investigate an alert by IDS regarding a potential C2 communication.

> **Username:** `Admin`
>
 **Password:** `elastic123`


## Task 2 : Scenario - Investigate a potential C2 communication alert

#### Scenario

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern `THM:{ ________ }`. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.  

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.


### How many events were returned for the month of March 2022?

Adjust the `time filter` to show the events that happended between **March 1 to March 31**

![header](img/1.png#center)

> Number of events - 1482

### What is the IP associated with the suspected user in the logs?

In the `fields pane` click on **source_ip** to view the IP addresses associated with the logs. We can't tell which IP is associated with the suspected user.

![header](img/2.png#center)

The second IP has fewer logs . Lets create a filter to view logs which pertain only to that IP address.

`_index:connection_logs AND source_ip:192.166.65.54`

![header](img/3.png#center)

We need to ensure if this is an C2C server. For that we can use `Alienvault`'s  Malware C2C database.

> Link - https://otx.alienvault.com/pulse/5c76b2acd1420a1aac451307

![header](img/4.png#center)

From the search result , we can see that the IP **104.23.99.198** is present in  their database hence confirming our doubt.

So the source_ip which is associated with the suspected user is found.

> Source_ip of suspected user - 192.166.65.54

### The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

Query - `_index:connection_logs AND user_agent:bitsadmin AND destination_ip :     104.23.99.190`

In the `Fields pane` , click on **user_agent** field to view what user agent was used to download files, there are 2 results - *Mozilla* & *bitsadmin*.

> _BITSAdmin_ is a command-line tool that you can use to create download or upload jobs and monitor their progress.


As seen before only 2 event's traffic is related to that IP address in which both the user_agent is **bitsadmin**.

![header](img/5.png#center)


### The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

Query - 

`_index:connection_logs AND user_agent:bitsadmin AND destination_ip :104.23.99.190 AND host: * `

where , 

- `host : *`  - represents any host.

![header](/img/6.png#center)

> File sharing site - pastebin.com

### What is the full URL of the C2 to which the infected host is connected?

The URI is  `/yTg0Ah6a`

![header](img/7.png#center)


> Full URL - pastebin.com/yTg0Ah6a 


### A file was accessed on the filesharing site. What is the name of the file accessed?

Visiting  pastebin.com/yTg0Ah6a gives us the name of the file,

![header](img/8.png#center)

> Filename - secret.txt

### The file contains a secret code with the format THM{_____}.

![header](img/9.png#center)

> Secret code - THM{SEC****E}
