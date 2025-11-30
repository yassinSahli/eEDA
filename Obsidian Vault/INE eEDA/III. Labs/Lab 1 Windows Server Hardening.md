# Lab Overview

The server team is ready to deploy a new server and needs you to configure your organization's standard security baselines before it is ready for production.

# Tasks

1. Create a new administrative account, set a complex password, and disable the built-in admin
2. Ensure Windows Firewall is enabled, and disable 3 inbound and 2 outbound firewall rules that are not needed on this server
    - All _Cast to Device_ rules
    - All _AllJoyn Router_ rules
    - _Dial Protocol Server_
3. Disable services that are not needed on this server
    - _AllJoyn Router_
    - All Bluetooth services
    - _Print Spooler_
    - _Telephony_
4. Enable all audit logging policies for both successes and failures
5. Block users from logging in or connecting Microsoft Accounts
# Workload

**Step 1 - Create a new admin account:** Open Computer Management and browse to Local Users and Groups, and then Users.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/1.png)

Right click on a blank area in the center of the window and choose _New User..._

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/2.png)

Enter in information for new administrator account, ensuring that _User must change password at next logon_* is **unchecked**, and click _Create_. Close New User window.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/3.png)

Now that the new user account has been created, we need to add it to the Administrators group. Browse the the _Groups_ folder in the Computer Management window and double-click on the _Administrators_ group.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/4.png)

To add the new account we created to this group, click on _Add..._ to bring up the Select Users window, type in the username of the new account you created, and then choose _Check Names_. If the name is underlined, you can choose _OK_. If not, check the spelling of the username to ensure you entered it correctly. This will be the same username you entered in **Step 3**.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/5.png)

Confirm that the new administrator account is listed in the group. Then choose _OK_ on the _Administrators Properties_ dialog box to save the changes.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/6.png)

**Step 2 - Change the password and disable the built-in Administrator account:** Now that the new admin account has been added to the administrators group, it's time to disable the built-in admin account.

Go back to the _Users_ folder in the Computer Management window, right click on _Administrator_ and choose _Set Password..._. Proceed past the warning.

Enter a new, complex and secure password for this account and choose _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/7.png)

Finally, to disable the built-in account, open the _Administator_ account. Check the box for _Account is disabled_ and click _OK_ to save.

**Step 3 - Disable unnecessary inbound firewall rules:** Open Windows Defender Firewall and verify that the Firewall has a status of _on_ for all network profiles in the center of the window.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/8.png)

Select _Inbound Rules_ on left, then select _AllJoyn Router (TCP-In)_ rule. Choose _Disable Rule_ on right hand side.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/9.png)

Repeat this process for: - _AllJoyn Router (UDP-In)_ - **ALL** _Cast To Device_ rules - Both _DIAL Protocol server (HTTP-In)_ rules (if two exist)

**Step 4 - Disable unnecessary outbound firewall rules:** With the Windows Defender Firewall still open, select _Outbound Rules_ in the left navigation

Perform the same steps as above to disable the following outbound rules: - _AllJoyn Router (TCP-Out)_ and _AllJoyn Router (UDP-Out)_ - **ALL** _Cast to Device_ rules

![[Pasted image 20251027113309.png]]

**Step 5 - Disable unnecessary services:** Close Windows Defender Firewall window and open _Services_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/11.png)

Find _AllJoyn Router Service_ in the list and double click (or right-click and choose Properties) to open the properties for the service. Change the _Startup type_ to _Disabled_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/12.png)

Repeat this same process for the following services: - **Both** _Bluetooth_ services - _Telephony Service_

Next, find the _Print Spooler_ service. Note that it is currently running.

Open the properties for that service and stop the service

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/13.png)

After the service has stopped, change the _Startup type_ from _Automatic_ to _Disabled_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/14.png)

**Step 6 - Configure Audit Logging Policies:** Close Services and open _Local Group Policy Editor_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/15.png)

In the left navigation section, expand _Computer Configuration_, then _Windows Settings_, _Security Settings_, and finally _Local Policies_. Then click on _Audit Policy_. Note how the main display changes to show additional settings

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/16.png)

Double click on _Audit account logon events_ at the top of the list to open it's properties.

Check both _Success_ and _Failure_ to enable both types of logging for this event type, and choose _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/17.png)

Repeat those actions for **ALL** of the Audit policies in this section: - Audit account management - Audit directory service access - Audit logon events - Audit object access - Audit policy change - Audit privilege use - Audit process tracking - Audit system events

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/18.png)

**Step 7 - Block Microsoft accounts:** 
Still in the _Local Group Policy Editor_, navigate to **_Security Options_** in the same tree you are currently in.
![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/19.png)

Find _Accounts: Block Microsoft Accounts_ in the list, and double-click to open its properties.

In the dropdown box, choose **_Users can't add or log on with Microsoft Accounts_**, and click _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3474/20.png)