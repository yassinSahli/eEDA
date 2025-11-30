# Lab Overview

In this lab, you will get a chance to explore Wireshark and how it can be used to investigate network traffic. We'll take a look at a PCAP file from a previous capture, as well as live traffic.

# Tasks

Begin your investigation by loading the PCAP file and checking the HTTP/S traffic contained within. Continue with a live capture of HTTP/S, ICMP, and DNS traffic as well.
1. Load the PCAP file and examine the HTTP and HTTPS traffic.
    - What user credentials were used to log in to the site?
    - Under what circumstances would the HTTPS traffic be readable?
2. Perform a live capture on interface **eth1**.
    - Ping the webserver at demo.ine.local and examine the result in Wireshark
    - Explore the site using a browser and examine that traffic as well
    - Continue by examining the page at **https://demossl.ine.com**. What is unique about the captured traffic?
3. Finish up by capturing traffic on the loopback interface and performing a DNS lookup

# Workload
**Step 1 - Examine the PCAP file on the desktop for HTTP traffic:** Open wireshark and load _capture.pcap_ located on the desktop

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/1.png)

Apply a display filter to only show traffic on TCP port 80: _tcp.port == 80_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/2.png)

You can see now that the extra traffic that was not on port 80 has been removed from the display.

Since we want to focus only on the HTTP traffic, and not the supporting TCP packets as well, let's adjust our display filter to only show HTTP traffic specifically: _http_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/3.png)

Look through the packets shown in the top pane to identify the pages that were loaded. You should see _portal.php_ and _login.php_ as well as various image files

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/4.png)

To get a more concise view of this HTTP traffic, let's follow the HTTP stream. Right click on packet number 6 and choose _Follow_ -> _HTTP Stream_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/5.png)

Examine this window to follow the logic of the pages that were loaded:

1. Original request to the root of the site: **GET / HTTP/1.1**
2. Redirect response to _portal.php_: **HTTP/1.1 302 FOUND**
3. Request for _portal.php_: **GET /portal.php HTTP/1.1**
4. Redirect response to _login.php_: **HTTP/1.1 302 FOUND**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/6.png)

1. Response with HTML of _login_.php_: *_HTTP/1.1 200 OK**
2. HTML code of requested page

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/7.png)

Since there was a GET request for a page named _login.php_, it could be a reasonable assumption that there may be a login attempt in this traffic as well.

Let's adjust our display filter to find any POST requests for this site: **http.request.method == POST**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/8.png)

We see that there is a single packet that matches out filter, and it is for _login.php_, so our suspicions may be confirmed. Let's take a deeper look at this packet by expanding out the _HTML Form_ data in the middle section of the window

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/9.png)

Expanding this section, we can see that this form was submitted with a _login_ value of _bee_ and a _password_ value of _bug_. Keep in mind, we can only see these credentials because this site is **NOT** using HTTPS and the traffic is in cleartext.

**Step 2 - Examine the HTTPS traffic:** Let's clear the display filter and start looking at the HTTPS traffic also contained in this capture file.

Set your display filter to **tcp.port == 443** to show all traffic on port 443

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/10.png)

After the initial 3-way handshake, we can see there are _TLSv1.2_ packets where the server and client are negotiating the encryption.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/11.png)

After this, we see a lot of packets that are just shown as TLS _Application Data_ (and the ACK packets acknowledging their receipt). This tells us that the traffic is encrypted and without the private key for the certificate, we will be unable to read this data.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/12.png)

**Step 3 - Examine a live capture of a ping request:** Close the packet capture file by going to _File_ -> _Close_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/13.png)

Now let's start a new capture on ETH1, by double-clicking on _eth1_ in the Capture section

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/14.png)

Now that the capture is running, open up a terminal window and ping the IP for demo.ine.local (192.211.95.3). Stop the ping after about 4 replies by using _CTRL-C_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/15.png)

Back in the Wireshark window, let's take a look at our results. You should have an amount of packets equal to twice the number of ping replies you received. For example, if you sent 4 ping requests and received 4 replies, you should have 8 packets that show **ICMP** as their protocol.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/16.png)

The packets in wireshark are structured so that after a request you have a reply (assuming the system is up and replies to pings). A ping is technically known as an _ICMP Echo Request_, which is why the protocol field shows **ICMP**.

Go ahead and take a look at some more of the information in those ping packets to see how they are built and how the replies are identified.

**Step 4 - Examine a live capture of web traffic:** Once you finish looking at the ping data, clear the captured data, but keep the capture running by selecting _Restart current capture_ in the toolbar

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/17.png)

Once cleared, go ahead and open up a web browser and go to **http://demo.ine.local**.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/18.png)

This is the same site that was used in the original capture file, so we won't go into detail on the capture here, but pay special attention to how many packets are transmitted and received as you browse around the site. Explore the packets that you capture in a little more depth to see how web requests are structured and processed.

After you've finished looking at the HTTP site, restart the capture again, but this time browse to **https://demossl.ine.local**. Notice how the requests are significantly different when browsing an HTTPS site versus an HTTP site.

**Step 5 - Capture DNS traffic:** Stop the capture and start a new one on the _loopback_ interface

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/19.png)

Notice how there is a lot more traffic that is being captured. This is similar to a production network capture where display and capture filters can be a huge help.

So let's stop this capture and then restart it, but using a capture filter this time instead.

Since we're looking specifically at DNS traffic now, let's set a capture filter of **udp port 53**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/20.png)

Now start the capture using the blue fin icon in the toolbar

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/21.png)

Return to the terminal window and perform an nslookup of _demo.ine.local_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD4490/LAB-3797/22.png)

Looking back at the Wireshark window, we can see the DNS response for both the A record and the AAAA record. (You may also see some other DNS traffic in there if you still have Firefox open)

![[Pasted image 20251110143034.png]]

Explore these DNS packets to see how they are constructed.
