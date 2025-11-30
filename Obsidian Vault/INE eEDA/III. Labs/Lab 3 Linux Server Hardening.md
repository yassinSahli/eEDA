# Lab Overview

When starting the lab, you will be placed onto the desktop of a Kali Linux machine. Connect to the lab server using the following: - Open up terminal and ssh to the server:  
`ssh inelab@target.ine.local` - Username: `inelab` - Password: `Q9G%B&u7J8Tr`

# Tasks

1. Examine the list of installed packages to determine if anything unnecessary is installed. Uninstall what is not needed.
2. Analyze the startup services on the server and ensure only what is necessary is running.
3. Secure the SSH server by preventing _root_ logins and requiring users to use keys to login.
4. Disable _root_ logins to the server.
5. Generate public/private keypair for the new admin user.
6. Configure the firewall to allow only required inbound services (e.g., SSH 22, HTTP 80, HTTPS 443), **apply iptables rules**, and make them **persistent** across reboots.

# Workload

**Step 1 - Examine installed packages:** 

Run the following command to show the list of installed packages:

```
sudo dpkg --list
```

Page through the list using **spacebar** to examine what packages are installed on this server. With this being a new installation, there is nothing that needs to be removed on this list. Press **Q** to exit this list.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/1.png)

```
# General inventory
dpkg -l | less

# Disk usage by installed packages (top 30)
dpkg-query -Wf='${Installed-Size}\t${Package}\n' | sort -n | tail -n 30 | column -t

# If snap/flatpak are present and not needed (common in labs), remove:
sudo apt-get purge -y snapd flatpak

# Remove GUI if this is a headless server (only if you are sure!)
# sudo apt-get purge -y xorg* xfce4* gnome* plasma* lightdm* sddm* --allow-change-held-packages

# Autoremove residual deps and clean cache:
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get clean
``
```

**Step 2 - Ensure there are no insecure management services in use:** 

Run the following command to remove the most common insecure services:

```
sudo apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server
```

We can see from the screenshot that none of those were installed.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/2.png)


```
# What’s running now
systemctl --type=service --state=running

# What is enabled at boot
systemctl list-unit-files --type=service | grep enabled

# Common services to disable on hardened servers (only if present and unneeded):
sudo systemctl disable --now avahi-daemon.service 2>/dev/null || true    # mDNS/zeroconf
sudo systemctl disable --now cups.service 2>/dev/null || true            # printing
sudo systemctl disable --now bluetooth.service 2>/dev/null || true
sudo systemctl disable --now rpcbind.service 2>/dev/null || true
sudo systemctl disable --now nfs-kernel-server.service 2>/dev/null || true
sudo systemctl disable --now smbd.service nmbd.service 2>/dev/null || true
sudo systemctl disable --now apache2.service 2>/dev/null || true         # if not using Apache
sudo systemctl disable --now nginx.service 2>/dev/null || true           # if not using Nginx
```


**Step 3 - List services on server:** 

To show all the services on this server and their status, run the following command:

```
sudo systemctl list-unit-files --type=service
```

Looking through this list, the default services are secure and do not need to be modified. Use **spacebar** to page through this list and then **Q** to exit.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/3.png)

```
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)

sudo sed -i \
 -e 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin no/' \
 -e 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication no/' \
 -e 's/^\s*#\?\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
 -e 's/^\s*#\?\s*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
 -e 's/^\s*#\?\s*UsePAM.*/UsePAM yes/' \
 /etc/ssh/sshd_config

# Optional: restrict to protocol 2 and a safer cipher/MAC set on older systems
# echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config

sudo systemctl restart ssh
sudo systemctl status ssh --no-pager
```

**Step 4 - Disable _root_ SSH logins:** 

Edit the sshd configuration file

```
sudo nano /etc/ssh/sshd_config
```

Find **PermitRootLogin** in the configuration, uncomment it (remove the **#**), and change the property to **no**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/4.png)

Press **CTRL+X** exit, answering **Y** to save the file and press **Enter** to overwrite the existing file.

Restart the _sshd_ service to immediately apply those settings to the SSH server

```
sudo systemctl restart sshd
```

```
# Lock root (prevents password-based login)
sudo passwd -l root

# Confirm root has no valid password hash now:
sudo awk -F: '/^root:/{print $1":"$2}' /etc/shadow
# It should show 'root:!' or 'root:*'
```

**Step 5 - Create new admin account**: 

Run the following commands to create a new account, set the password, and add it to the _sudo_ group:

```
sudo useradd -m -c "New Admin" newadmin
sudo passwd newadmin
sudo usermod -aG sudo newadmin
```

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/5.png)

Disable root logins by editing the _/etc/passwd_ file

```
sudo nano /etc/passwd
```

Find the line that shows the **root** account and look at the end of it. (Should be top line)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/6.png)

Change **/bin/bash** to be **/usr/sbin/nologin** to prevent the _root_ account from being able to interactively login.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/7.png)

**Step 6 - Generate private/public keypair for new admin:** 

Open a new terminal tab on the Kali machine

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/8.png)

Type the following command to generate a new keypair:

```
ssh-keygen -t rsa
```

**ENTER A PASSPHRASE. DO NOT LEAVE IT BLANK**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/9.png)

On the Linux server, temporarily allow password logins for SSH:

```
sudo nano /etc/ssh/sshd_config
```

Find the line with **PasswordAuthentication** and set it to **Yes**. Use **CTRL+X** to exit, **Y** to save, and **Enter** to overwrite the existing file.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/10.png)

Restart the SSH server again:

```
sudo systemctl restart sshd
```

Back in the Kali terminal tab, upload the newly generated public key to the Linux server. Enter the password you created for the _newadmin_ account

```
ssh-copy-id newadmin@target.ine.local
```

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/11.png)

**Step 7 - Test the new SSH Login:** 

On the Linux server, disable password logins by reversing the earlier step: - Edit the configuration file

```
sudo nano /etc/ssh/sshd_config
```

Change **PasswordAuthentication** back to **No**, **CTRL+X** to exit, **Y** to save, and **Enter** to overwrite the file.

- Restart the SSH server again
    
    ```
    sudo systemctl restart sshd
    ```
    

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/12.png)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/13.png)

On the Kali machine, SSH to the server using the private key now:

```
ssh newadmin@target.ine.local
```

Enter the passphrase you created when generating the keypair

Once connected, use the **whoami** command to verify that you are logged in as _newadmin_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3476/14.png)

[!] Create Admin User & Generate SSH Keypair [!]

```
# # On the Server
# Replace 'adminy' with your preferred username

NEWADMIN=adminy
sudo adduser "$NEWADMIN"
sudo usermod -aG sudo "$NEWADMIN"
```

```
# On Kali (not on the Target Server)

ssh-keygen -t ed25519 -a 100 -f ~/.ssh/${NEWADMIN}_ed25519 -C "${NEWADMIN}@target.ine.local"
ssh-copy-id -i ~/.ssh/${NEWADMIN}_ed25519.pub ${NEWADMIN}@target.ine.local
ssh -i ~/.ssh/${NEWADMIN}_ed25519 ${NEWADMIN}@target.ine.local
sudo -v   # verify sudo works
```

```
# On the Target Server

sudo systemctl restart ssh
sudo systemctl status ssh --no-pager
```

**Step 8 - Configure iptables Rules & Make Them Persistent**

We need to **allow** only essential inbound traffic (SSH 22, HTTP 80, HTTPS 443). 
Then **drop** unsolicited input, permit established traffic, and persist across reboots.

```
# Flush existing rules (optional if you want a clean slate)
sudo iptables -F
sudo iptables -X

# Default policies: drop unsolicited inbound/forward; allow local out
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related traffic
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH, HTTP, HTTPS
sudo iptables -A INPUT -p tcp --dport 22  -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80  -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# (Optional) ICMP echo for troubleshooting
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Verify rules
sudo iptables -L -n -v
```

**Option 1 — iptables-persistent (recommended on Debian/Kali):**
```
sudo apt-get update
sudo apt-get install -y iptables-persistent

# Save both IPv4 and IPv6 (if you set v6 rules; below saves v4 only)
sudo netfilter-persistent save
# Files:
#   /etc/iptables/rules.v4

#   /etc/iptables/rules.v6
```

**Option 2 — Manual save/restore via systemd:**

```
# Save current rules
sudo mkdir -p /etc/iptables
sudo sh -c 'iptables-save > /etc/iptables/rules.v4'

# Create a systemd unit to restore at boot
sudo tee /etc/systemd/system/iptables-restore.service >/dev/null <<'UNIT'
[Unit]
Description=Restore iptables firewall rules
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecReload=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now iptables-restore.service
```

**Validation & Verification**
```
sudo iptables -D INPUT -p tcp --dport 80  -j ACCEPT
sudo iptables -D INPUT -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

**Rollback/Recovery Tips**

```
sudo iptables -P INPUT ACCEPT
sudo iptables -F
```