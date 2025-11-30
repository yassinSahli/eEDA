# Lab Overview

In this lab, we'll be configuring various firewall rules on a Cisco ASA. For our purposes, we'll be working in the CLI so you can become more comfortable with the commands required to configure access lists.

Please keep in mind, this is a very simple network configuration. Most enterprise environments will be more complex than this, and may require more complex firewall rules.

# Tasks
For this lab, our network is constructed as shown below. Please note, the only devices actually present in this lab are the Kali workstation you will be logged in to, and the firewall itself. The other servers and workstations are only shown on the map, but do not exist in the lab - so they will not respond to any traffic.

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/1.png)

You have been tasked with setting up firewall rules for a new environment. The organization has the following needs:

1. Allow email traffic inbound on port 25 from anywhere on the internet to EMAIL01
2. Allow web traffic inbound on ports 80 and 443 from anywhere on the internet to WEB01
3. Block inbound email traffic on port 25 from a malicious email server at 123.45.67.89
4. Allow email traffic outbound on port 25 from EMAIL01 to any other email server on the internet
5. Allow outbound web traffic from the SALES VLAN to the internet on ports 80 and 443

# Workload
**Step 1 - Log in to the firewall and switch to configuration mode:**
Start by opening up a terminal window and connecting with SSH to 192.168.10.5. Use the following credentials and accept the key if/when prompted:

- Username: **inelab**
- Password: **sh@c_y#tVLA9U2r**

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/2.png)

Enter `en` at the prompt to switch to enable mode and enter **rzjtLwqc8*^6sDHU** as the password. You will notice the prompt changed from **ciscoasa>** to **ciscoasa#**.

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/3.png)

Finally, to enter configuration mode, type `conf t` at the prompt and press Enter. You will notice the prompt change to **ciscoasa(config)#**

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/4.png)

**Step 2 - Allow inbound traffic on port 25 from anywhere to EMAIL01**

Recalling how an ACL is built, use the following command to allow traffic from anywhere to 192.168.10.25:

```
access-list SMTP extended permit tcp any host 192.168.10.25 eq smtp
OR
access-list SMTP extended permit tcp any host 192.168.10.25 eq 25
```

Let's break down this command so that you understand exactly why it is entered this way

- `access-list` - tells the firewall we are configuring an access list on the device
- `SMTP` - is the label or name we are assigning to this access list
- `extended` - allows us to specify both a source and destination for the rule
- `permit` - allow the traffic through
- `tcp` - traffic should use TCP protocol
- `any` - this is the source of the traffic for this rule. In this case, any source
- `host` - the destination will be a single host
- `192.168.10.25` - the IP address of the destination
- `eq` - the port number for this rule will equal whatever port is entered in the next portion
- `smtp` - the port that this rule applies to (can also be entered as the port number, ie: 25)

If you entered the command without errors, pressing Enter will return you back to the prompt. You can verify the rule by using the _show_ command to show our running configuration for access lists:

```
show run access-list
```

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/5.png)

**Step 3 - Allow inbound traffic from anywhere on ports 80 and 443 to WEB01**

Enter the following two commands to create new entries that allow tcp traffic from anywhere on ports 80 and 443 to the host at 192.168.10.80.

```
access-list WEB extended permit tcp any host 192.168.10.80 eq 80
access-list WEB extended permit tcp any host 192.168.10.80 eq 443
OR
access-list WEB extended permit tcp any host 192.168.10.80 eq http
access-list WEB extended permit tcp any host 192.168.10.80 eq https
```
Note that in CISCO ASA:
![[Pasted image 20251106104322.png]]

Similarly to our email rules, you can use either the port number, or the well known port name in the rule. In this case, you can substitute _www_ for port 80 and _https_ for port 443.

Once you have entered those rules, you can run `show run access-list` again to verify they were entered correctly. Also note, that if you entered the port numbers, they were changed to reflect the well known port name instead.

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/6.png)

**Step 4 - Block inbound traffic on port 25 from the malicious server at 123.45.67.89 to EMAIL01**

Let's switch gears for a minute and now block traffic coming from a single source (123.45.67.89) on the internet. This server was identified as a malicious email server sending spam to our organization.

```
access-list BLOCK_SMTP extended deny tcp host 123.45.67.89 host 192.168.10.25 eq smtp
```

Notice how we are now using a `deny` entry instead of permit, and have specified a host IP for both our source and destinations on this rule.

As usual, let's verify the rule was entered correctly using `show run access-list`

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/7.png)

Our list of access rules continues to grow.

**Step 5 - Allow outbound email traffic on port 25 from EMAIL01 to anywhere**

Now we need to allow traffic from the email server on port 25 out to the internet so the users can send email externally:

```
access-list OUTBOUND_SMTP extended permit tcp host 192.168.10.25 any eq 25
OR
access-list OUTBOUND_SMTP extended permit tcp host 192.168.10.25 any eq smtp
```

This rule is slightly different from previous ones, and we are allowing traffic outbound, so we use a specific source, but use **any** for the destination.

Let's show the config to verify again: `show run access-list`

![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/8.png)

**Step 6 - Allow outbound web traffic on ports 80 and 443 from the Sales VLAN to the internet**

Finally, let's allow our sales department to reach the internet to browse the web:

```
access-list OUTBOUND_WEB extended permit tcp 192.168.20.0 255.255.255.0 any eq www
access-list OUTBOUND_WEB extended permit tcp 192.168.20.0 255.255.255.0 any eq https
```

These entries are also slighty different, where we are not specifying a certain host, but instead allowing traffic from an entire subnet. So in this entry, our source becomes `192.168.20.0 255.255.255.0` to indicate the subnet itself.

Let's run a `show run access-list` one final time to verify our rules before we save the configuration.
![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/9.png)

**Step 7 - Save the running config**
Use one of the following commands to save the configuration.

```
write memory
OR
copy run start
```
![Content Image](https://assets.ine.com/content/labs/networking-labs/LAB-3796/10.png)