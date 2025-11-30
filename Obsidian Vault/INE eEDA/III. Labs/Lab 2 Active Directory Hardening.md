# Lab Overview

The server team is beginning to build the first Active Directory structure for the business and would like you to ensure the environment is properly secured before continuing. Some users have already been created as part of this process.

# Tasks

1. Remove excess permissions from Jane Doe's account
2. Configure domain password policies based on the following requirements:
    - 5 passwords remembered
    - Password expiration set to 180 days
    - Users cannot change passwords within 5 days of setting their password
    - Passwords must be at least 12 characters long
    - Passwords cannot be stored using reversible encryption
3. Configure account lockout policies based on the following requirements:
    - Accounts remain locked out for 60 minutes
    - 5 failed logins to trigger the lockout
    - The lockout count should reset after 30 minutes
4. Configure PowerShell settings domain-wide to strictest settings for script execution
5. Enable PowerShell logging for all script activity
6. Block all users except _inelabadmin_ from running PowerShell

# Workload

**Step 1 - Check Jane's permissions:** 
Open Active Directory Administrative Center and browse to the _Lab Users_ OU.
![[Pasted image 20251027144253.png]]

![[Pasted image 20251027144304.png]]

Right click on **Jane Doe** to open the properties for the account, then choose _Extensions_ on the left, and then the _Security_ tab.
![[Pasted image 20251027144527.png]]

Scroll until you see specific permissions for **Jane Doe (janedoe@lab.ine.local)** in the _Principal_ column.
![[Pasted image 20251027144744.png]]

Looking at these permissions, we see that Jane has Full control to the **Lab Users** OU, even though she is not an administrator.

Next, we will want to look at the permissions for that OU specifically. Click _Cancel_ on the property boxes for Jane, then switch to the "Tree View" tab in Active Directory Administrative Center (if not already there).

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/4.png)

Right click on the **Lab Users** OU and choose _Properties_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/5.png)

With that dialog box open, choose the _Security_ tab near the bottom of the window and then click _Advanced_ under the permissions list.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/6.png)

Locate the entries that list Jane Doe as the Principal and remove each of them by clicking on the individual line and then clicking _Remove_.
![[Pasted image 20251027145017.png]]

When all 4 entries have been removed, click _OK_ and then close the properties box for the Lab Users OU.

**Step 2 - Set Group Policy options for password requirements:** Close the Active Directory Admin Center and open **Group Policy Management** from the desktop

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/8.png)

Expand the navigation on the left hand side -> _Forest: lab.ine.local_ -> _Domains_ -> _lab.ine.local_ -> _Group Policy Objects_ and right click on **Default Domain Policy** and choose _Edit_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/9.png)

To reach the password settings, in the new _Group Policy Management Editor_ window that opens, expand the navigation as follows:

_Computer Configuration_ -> _Policies_ -> _Windows Settings_ -> _Security Settings_ -> _Account Policies_. Then click on **Password Policies** where you will see the policies appear in the main window.
![[Pasted image 20251027145456.png]]
Set each of the following policy settings by double clicking on the policy, setting it appropriately, and clicking _OK_: - **Enforce password history**: **5** passwords remembered

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/11.png)

- **Maximum password age**: Password will expire in **180** days

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/12.png)

- **Minimum password age**: Password can be changed after **5** days

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/13.png)

- **Minimum password length**: Password must be at least **12** characters

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/14.png)

- **Store passwords using reversible encryption**: **Disabled** (this should already be set this way)

**Step 3 - Set Account Lockout Policies:** 

Still in Group Policy Management Editor, navigate to **Account Lockout Policy** in the left navigation. You will see the policies appear in the main window.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/15.png)

Set **Account lockout duraction** to **60** minutes, and click _OK_.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/16.png)

Accept the other suggested settings

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/17.png)

The other two settings will be set appropriately automatically, based on the suggested settings that were applied.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/18.png)

**Step 4 - Configure PowerShell script execution policy**

Still in the Group Policy Management Editor, browse to **Computer Configuration -> Policies ->_Administrative Templates_ -> _Windows Components_ -> _Windows PowerShell** in the left hand navigation.

![[Pasted image 20251027150022.png]]
![[Pasted image 20251027150136.png]]

Double click **Turn on Script Execution** to open it's properties and set it to **Disabled**. Click _OK_.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/21.png)

This will disable script execution, effectively setting the Script-Execution setting to **Restricted**

** Step 5 - Enable PowerShell logging:** This will enable logging for PowerShell command and script processing.

Double click on **Turn on PowerShell Script Block Logging** and set it to **Enabled**. Click _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/22.png)

**Step 6 - Block PowerShell application for all users except the _inelabadmin_ user**

Open _Active Directory Administrative Center_ and browse to the _Lab Users_ OU. Right click in the blank area of the main window and select **New** and then **Group.**
![[Pasted image 20251027151135.png]]

Enter **allow-powershell** for the _Group Name_. The _Group (SamAccountName)_ field will automatically populate.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/24.png)

Scroll down to the **Members** section and choose **Add** (Be careful not to do this in the _Member Of_ section).

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/25.png)

Enter _inelabadmin_ into the dialog box and click _Check Names_. Once the name updates and is underlined, click _OK_. If the name is not underlined, or you receive another message, double check the spelling of the username you typed in.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/26.png)

Confirm that **INE Lab admin** appears in the _Members_ section, and click _OK_ to close the dialog box.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/27.png)

Now go back to _Group Policy Management_. Ensure you are **NOT** in **Group Policy Management _Editor**.

Right click on **Group Policy Objects** and select _New_. Enter _Block Powershell_ for the new GPO name and click _OK_.

Forest: lab.ine.local
  └── Domains
      └── lab.ine.local
          └── Group Policy Objects

![[Pasted image 20251027151811.png]]


![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/28.png)

Right click on the newly created policy and choose _Edit..._

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/29.png)

In the new Group Policy Management Editor window that appears, navigate to **User Configuration_ -> _Policies_ -> _Windows Settings_ -> _Security Settings_ -> _Software Restriction Policies_**.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/30.png)

Right click on _Software Restriction Policies_ and select _New Software Restriction Policies_

In the main section of the window, double-click on **Additional Rules**, then right click in the blank area of that section and select _New Path Rule..._
![[Pasted image 20251027152125.png]]

Enter **%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe** in the _Path_ field. Select **Disallowed** for the _Security level_, and click _OK_.
![[Pasted image 20251027152552.png]]
![[Pasted image 20251027152642.png]]
Close the _Group Policy Management Editor_ window and return to the _Group Policy Management_ window. (Yes, those two can be confusing).

Select your newly edited **Block Powershell** policy and go to the **Delegation** tab. Click on **Add...** at the bottom of the window.

Enter **allow-powershell** (the name of the group we previously created) into the dialog box and click on _Check Names_. Once the name is underlined, click _OK_ to save. If you receive an error or other dialog box, check the spelling of the group name.

![[Pasted image 20251027152957.png]]

Click _OK_ on the **Add Group User dialog** that appears to accept the default settings, then click on _Advanced..._ on the bottom right.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/35.png)

Go to **Advanced
![[Pasted image 20251028151745.png]]


![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/36.png)

Click **Yes** on the warning dialog that appears.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/37.png)

To apply our newly created policy, right click on the **Lab Users** OU and choose **Link and Existing GPO...**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/38.png)

Select the **Block Powershell** policy and click _OK_ to link it to that OU.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/39.png)

To verify the GPO is properly linked, expand the **Lab Users** OU and verify the linked policy appears.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-4467/LAB-3475/40.png)