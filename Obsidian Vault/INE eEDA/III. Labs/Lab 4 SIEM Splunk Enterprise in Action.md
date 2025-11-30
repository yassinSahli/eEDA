# Lab Overview

In this lab, you will get familiar with using Splunk as a SIEM and some of the basic workflows in the system. You'll perform multiple different searches based on different criteria, in addition to creating visualizations from those searches.

**NOTE:** This lab is based on the [Boss Of The SOC (BOTS) v3](https://github.com/splunk/botsv3) dataset released by Splunk. Credits to Ryan Kovar, David Herrald, James Brodsky, John Stoner, Jim Apger, David Veuve, Lily Lee, and Matt Valites for sharing the Splunk detection tips this lab covers with the public, through this dataset.

---

**Please be advised that this dataset may contain profanity, slang, vulgar expressions, and/or generally offensive terminology.**

This dataset contains evidence captured during actual computer security incidents, or from realistic lab recreations of security incidents. As such, the dataset may contain profanity, slang, vulgar expressions, and/or generally offensive terminology.

# Tasks
Your organization has tasked you with identifying various security issues in the environment. You'll be using Splunk to search and analyze the logs for the following:

1. Are there any IPs that have excessive blocked connections in the Cisco ASA firewall?
2. Create an alert to notify the security team if any accounts are added to the local administrator group on any system (EventID 4732)
3. Identify if there is any suspicious activity occuring on endpoints using Symantec Endpoint Protection information.

# Workload
---
**Step 0 - Engineering & Datasets** 
Open Settings > DATA > Indexes
![[Pasted image 20251029110349.png]]

Explore different datasets & indexes: 
![[Pasted image 20251029110454.png]]This is where we're going to store the data

Let's explore where our data comes from: 
![[Pasted image 20251029110925.png]]
## **Data Pushed to Splunk (Forwarders)**

Splunk Forwarders are agents installed on other systems that **send data to Splunk**.
- **Suricata IDS logs** sent via a **Universal Forwarder** (UF) from `/var/log/suricata/eve.json`.
- **Linux audit logs** forwarded from `/var/log/audit/audit.log`.
- **Windows Event Logs** pushed from a Windows server using a forwarder.
### Methods:
- **Universal Forwarder (UF)**  
    Example:
    - Forward Suricata logs from `/var/log/suricata/eve.json` to Splunk indexer.
- **Heavy Forwarder (HF)**  
    Example:
    - Preprocess and forward Palo Alto firewall logs with field extraction.
- **HTTP Event Collector (HEC)**  
    Example:
    - A Python script sends JSON-formatted Suricata alerts to Splunk via HTTP POST.
## **Data Pulled by Splunk (Inputs)**

Splunk can **collect data directly** from sources using built-in inputs.
- **Monitor Suricata logs** locally:  
    Splunk watches `/var/log/suricata/eve.json` using a file monitor input.
- **Listen for syslog traffic** on UDP port 514.
- **Pull AWS CloudTrail logs** using the AWS Add-on.
- **Collect metrics from a REST API** using a scripted input.
### Methods:
- **File & Directory Monitoring**  
    Example:
    - Monitor `/var/log/suricata/eve.json` directly on the Splunk server.
- **Network Inputs (TCP/UDP)**  
    Example:
    - Listen on UDP port 514 for syslog messages from routers or firewalls.
- **Scripted Inputs**  
    Example:
    - Run a Python script to fetch threat intel feeds and ingest them.
- **Modular Inputs / Add-ons**  
    Example:
    - Use the Splunk Add-on for AWS to pull CloudTrail logs.
- **Database Inputs (DB Connect)**  
    Example:
    - Pull login events from a PostgreSQL database.
## eg: Network Devices Setup
![[Pasted image 20251029111354.png]]
### Select Source: 
![[Pasted image 20251029111713.png]]

### Input Settings:
![[Pasted image 20251029111915.png]]

As for the index: 
- The Splunk platform stores incoming data as events in the selected index. 
- It's highly recommended to create a new index type for each  
![[Pasted image 20251029113130.png]]

![[Pasted image 20251029113532.png]]

![[Pasted image 20251029113437.png]]

Review:
![[Pasted image 20251029113448.png]]
![[Pasted image 20251029113503.png]]

---

**Step 1 - Open Splunk and list available sourcetypes:** 
Open Splunk using the desktop shortcut
![[Pasted image 20251029110517.png]]
Once opened, click on **Search & Reporting** in the left-hand navigation
![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/67be476978cc3a7b5a8d1103605f12bb5c316f455dba62954ce34db038b0dd6e.png)

In the search dialog box let's begin by executing a simple SPL query to output all events for **all time**
![[Pasted image 20251029142401.png]]
--> 2,083,056 events detected

Let's use the following SPL to list all sourcetypes (ASA, syslog, WinEventLog, AWS cloudwatchlogs etc...):

```
index="botsv3" | stats count by sourcetype | sort - count
```

_Note: it may take a few minutes for this search to complete_
![[Pasted image 20251029142703.png]]

---

**Step 2 - Identify the sourcetype to use for the Cisco ASA firewall:** 

Look through the list of sourcetypes until you find **cisco:asa**. Click on that entry.

![[Pasted image 20251029142738.png]]

Once the search completes, you will see a list of all the events from the ASA. However, we are only concerned with _blocked_ events for our purpose.

```
index="botsv3" sourcetype="cisco:asa"
```

To narrow this search down further, click on **action** under _INTERESTING FIELDS_ on the left, and choose **blocked**
![[Pasted image 20251029142816.png]]

Now we have a list of all of the blocked events. But we can't determine which IPs that have excessive blocked connections in the Cisco ASA firewall as we can see bellow: 
![[Pasted image 20251029142929.png]]

It's time to narrow this down even more and only see the blocked IP addresses, and how many times each was blocked. To do that, add the following to the end of the existing search:

```
index="botsv3" sourcetype="cisco:asa" | stats count by src_ip | sort - count
```

Now your search should look like this
![[Pasted image 20251029143229.png]]

Once the search completes, we can then eliminate all IPs that begin with _192.168_ to filter out internal addresses. Modify your search by adding the following **BEFORE** the first pipe character (|):

```
src_ip!="192.168.*"
```

Your search should now look like this
![[Pasted image 20251029143435.png]]

From our filtered results, we can see that **34.215.24.225** has been blocked much more frequently than any other IP address. Let's find out what this IP is doing now.

Click on the IP address in the search results, and then click on **View events**

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/18129e8fc40c80f581327e66c7e955226347a40981939d2b040b647ee973894b.png)

Now that we are filtering on a specific IP address, we can remove our exclusion for the 192.168.0.0 subnet. Delete the following text from the search box:

```
index="botsv3" sourcetype="cisco:asa" action=blocked src_ip="34.215.24.225"
```

Our search criteria should now look like this
![[Pasted image 20251029143622.png]]

Next, we want to see what ports this suspicious IP is attempting to connect to. So let's modify our search to add the following to the end of it:

```
index="botsv3" sourcetype="cisco:asa" action=blocked src_ip="34.215.24.225" | stats count by dest_port | sort - count
```

Here's what the search should look like
![[Pasted image 20251029143822.png]]

From our results, we can tell this IP is more than likely attempting a **port scan** against our perimeter network, and should be permanently blocked.

---

**Step 3 - Identify sourcetype for Windows security logs and begin search:**  
Let's repeat our fist search to show the full list of sourcetypes. Again, make sure you have the correct timeframe selected (All Time):

```
index="botsv3" | stats count by sourcetype | sort - count
```

Find **WinEventLog:Security** in the list of sourcetypes and click on it to pull the full list of events
![[Pasted image 20251029152159.png]]
![[Pasted image 20251029152228.png]]

Next, we want to filter this list based on the Event ID of 4732.(**Refers to a new member was added to a security-enabled local group**)

To do that search for **EventCode** in the fields menu and  search for **4732**
![[Pasted image 20251029152511.png]]

```
index="botsv3" sourcetype="WinEventLog:Security" EventCode=4732
```

Your full search should look like:
![[Pasted image 20251029152717.png]]

Now we have a list of all events with the Event ID of 4732. We want to narrow this down further to only show ones that are for the local admin group.

The easiest way to do this is to add Admin* to the search: 
```
index="botsv3" sourcetype="WinEventLog:Security" EventCode=4732 Admin*
```

![[Pasted image 20251029152808.png]]

This shows us that there has been one event where the local admin group was modified on an endpoint. 
![[Pasted image 20251029152947.png]]
This should definitely be investigated!

---

**Step 4 - Identify sourcetypes for Symantec events:**

Repeat our initial search to show all sourceyptes, but this time we're going to sort by sourcetype, not count (Symantec is an Advanced Endpoint Protection used to **protect data and workflows** associated with **all devices that connect to the corporate network**)

```
index="botsv3" | stats count by sourcetype | sort - sourcetype
```
Looking at the list of sourcetypes available, we see there are multiple Symantec sourcetypes.
![[Pasted image 20251029153140.png]]

To search them all, we can use a wildcard:

```
index="botsv3" sourcetype="symantec*"
```

This shows us all of the events for all Symantec sourcetypes.
![[Pasted image 20251029153243.png]]

---

**Step 5 - Show only blocked events:**

Now, similar to the Cisco ASA search, we want to only show blocked events for the Symantec data. Click on **action** (the lowercase option) in the left bar under _INTERESTING FIELDS_ and then click on **blocked**. This will filter our search

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/86f7004a65426fbcd1e6c6379271b45d94c41eac1cd1fdf13ff62c13b482ffe5.png)
![[Pasted image 20251029153319.png]]

Now that we have all of the events, we can group those events to show as blocked events by endpoint. The field we'll use for this is _Host_Name_.
![[Pasted image 20251029153449.png]]

Modify your search to include this filter

```
index="botsv3" sourcetype="symantec*" action=blocked | stats count by Host_Name
```

We can now see how many blocked events there are per endpoint

![[Pasted image 20251029153756.png]]

Let's create a visualization and add that to our existing security dashboard. To do that, simply click on the **Visualization** tab just above the search results.

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/41325837d5ab0a7215a27df52d60347cef8a56d6cc7e2bdaddc42dffc470fa21.png)

For the visualization type, choose the Pie Chart option

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/06727fa86dddb50479d6da7079d1a30cb25ec3a7fa85c29c8998205f9f65421e.png)

You shoud now have a visualization that appears similar to this:

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/48a83f0cec30eb8838f16e212650dea1a03a0c09910343c0bebffbe0cf0e3264.png)

Now, we can save this search and visualization to our existing _Security Dashboard_. To do that, click on **Save As** above the search bar, and choose **Existing Dashboard**

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/32d0013a031c992a2fa4e81d2fd0bfabd369ad618460f594210b4f3222a82497.png)

Select **Security Dashboard** for the dashboard to save to, and optionally give this panel a title

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/82a55450ccc4f0836a2c69aab9f75b8b5722f89cf77fdf9a0235386a5423de4d.png)

To see this new panel in our dashboard, select **Dashboards** in the top navigation bar and then click on **Security Dashboard** at the bottom of the list

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/b5c0a0e1f2b0c4a192c08a026349cc26e7648d8972b047c3a33f62f591e830b6.png)

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/6e64765b86c36debdaf6434eaf73dc323becdb9384cc5be0e9a7d8a71f6bf438.png)

We now see the complete dashboard, including the panel we just created.

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/e109ba2b773fa24e25d656cc417879a25a3949b984f9d1f14a23c85c8cfd202a.png)

If you want, you can click on **Edit** at the top and move the panel around, so it looks less awkward at the bottom by itself...

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/e2b1540dfdfad595e0b9da2856b0eb1c0cd6dc4f6526754355d153e6c77b975d.png)

Then you can click and drag the panel around and place it somewhere a bit more astetically pleasing

![Content Image](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/sme/newproc/924b35f224af1021d4f50313f25eab19799dc2639786cbc24c6b31e6825b6419.png)

Don't forget to **Save** at the top when you're done!

---

