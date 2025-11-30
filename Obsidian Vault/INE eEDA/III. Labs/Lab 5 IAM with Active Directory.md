# Lab Overview

In this lab, you will become familiar with setting up both Discretionary Access Control and Role-Based Access control in an Active Directory environment. In addition, you will take a look at audit configuration and event logs related to file access.

**Please Note: The configuration in this lab (domain controller and file server on same server) is for LAB PURPOSES ONLY. For security and performance reasons, this type of configuration should not be used in a production environment.**

# Tasks
Your organization is setting up a new file sharing structure and has tasked you with ensuring that access is set up properly for the various departments. In addition, they want to ensure that proper logging and auditing is configured.

1. Configure a new GPO for file system access and audit policy changes
2. Grant the 3 users individual access to the _All Company_ share and change the owner to Susan Langford
3. Configure three roles in AD (Sales, Engineering, Executive Leadership), configure permissions as appropriate, and add users to the groups as appropriate for their job role.
4. Ensure that proper auditing settings are configured on the file shares
5. Verify events appear in the Windows Event Viewer for file actions


# Workload
---
**Step 1 - Configure a new group policy object for auditing:** 

Open _Group Policy Management_ from the _Administrative Tools_ folder under the _Start menu_ and create a new policy under _Group Policy Objects_.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/1.png)

![[Pasted image 20251110104617.png]]
Name the policy, and then open the newly created policy to edit it.

Navigate to **Computer Configuration** -> **Policies** -> **Windows Settings** -> **Security Settings** -> **Local Policies** -> **Audit Policy**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/2.png)

Open **Audit object access** and modify it to Audit both _Success_ and _Failure_

![[Pasted image 20251110104821.png]]

Then, navigate to **Computer Configuration** -> **Policies** -> **Windows Settings** -> **Security Settings** -> **Advanced Audit Policy Configuration** -> **Audit Policies** -> **Object Access**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/4.png)

Modify **Audit File System** and **Audit File Share** to log both _Success_ and _Failure_ as well

![[Pasted image 20251110105000.png]]

![[Pasted image 20251110105045.png]]

In the same **Audit Policies** section, navigate to **Policy Change**

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/7.png)

Modify **Audit Policy Change** to log both _Success_ and _Failure_

![[Pasted image 20251110105223.png]]

All of these configured policies will allow us to log when when shared files are accessed (with one more step in the file system), as well as logging if anyone modifies the audit logging policy.

**Step 2 - Apply our policy to the correct OU.:** 

Since we are working with a domain controller in this instance (again, not recommended for production purposes), we want to link this new policy to the _Domain Controllers_ OU.

1. Close the _Group Policy Management Editor_ and return to _Group Policy Management_. 
2. Find the newly created policy by expanding **Group Policy Objects** and look for the one named *Lab policy*.

Click and drag this policy onto the _Domain Controllers_ OU.
![[Pasted image 20251110105732.png]]

You should then receive a confirmation dialog asking if you want to link the GPO. Click _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/10.png)

Although it may not be entirely necessary, you may want to force the group policies to update by opening a command prompt/PowerShell window and using the command _gpupdate /force_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/11.png)

**Step 3 - Set proper auditing permissions on the _All Company_ share:** 

Open Windows Explorer and navigate to _C:\Files Shares_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/12.png)

Right click on _All Company_ to open up the Properties window

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/13.png)

Choose the _Security_ tab and then select _Advanced_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/14.png)

Select the _Auditing_ tab and click on _Add_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/15.png)

Click on _Select a principal_ at the top, and then enter _everyone_ in the dialog box, and choose _Check Names_. Click _OK_ to save.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/16.png)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/17.png)

Set the following options, and choose _OK_ once verified: 
- Type: _All_ 
- Applies to: _This folder, subfolder and files_ 
- Basic Permissions: _Modify, Read & Execute, List Folder Contents, Read, Write_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/18.png)

**Step 4 - Utilizing a DAC model, set the owner and proper permissions on the _All Company_ share:** 
Next to _Owner_, click _Change_

![[Pasted image 20251110111536.png]]

In the dialog box, enter _susan_, click on _Check Names_, and then _OK_ once the name is underlined. If it is not underlined after clicking on _Check Names_, verify what you typed is correct.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/20.png)

Now that Susan is set as the owner, check the box to _Replace owner on subcontainers and objects_, and then Click _OK_ on this dialog box.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/21.png)

Back on the properties dialog for this folder, ensure you are on the _Security_ tab and then choose _Edit..._ to modify the permissions for this share.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/22.png)

Choose _Add..._, and then in the dialog box enter `john; jane; susan`, click _Check Names_ to ensure they are all verified, and then click on _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/23.png)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/24.png)

Individually set Jane, John, and Susan's permissions by selecting each of them one at a time, and checking the _modify_ box under _Allow_. Once they are all set, click _OK_ and then _OK_ again on the next dialog to save our permissions.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/25.png)

**Step 5 - Using an RBAC model now, we will configure permissions to the departmental folders:** 

Open _Active Directory Administrative Center_, switch to the tree view by clicking the tab on the right in the navigation bar, and then right click on *lab (local).

Select _New ->_ and then _Organizational Unit_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/26.png)

Name this OU _Groups_ and choose _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/27.png)

Navigate to the newly created OU, click anywhere in the empty space in the middle pane, choose _New ->_ and then _Group_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/28.png)

Name this group _Sales_, and then click _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/29.png)

Repeat that process for two more groups: _Engineering_ and _Executive Leadership_

We should now have 3 groups in this OU:

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/30.png)

Going back to the file shares in Windows Explorer, for each of _Engineering_, _Executive Leadership_, and _Sales_, we will give those newly created groups permissions to their applicable folder.

Starting with Engineering, right click on the folder name, go to the _Security_ tab and click on _Edit..._
Choose _Add..._ And then enter `engineering` in the box, click _Check Names_ and then _OK_.
![[Pasted image 20251110112643.png]]

Ensure that the new Engineering group has been granted _modify_ permissions by checking the appropriate box, and then click _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/34.png)

Repeat those steps for both the Executive Leadership and Sales folders.

**Step 6 - Add the users to their appropriate role:** 

Back in Active Directory Admin Center, ensure you are in the _Groups_ OU.

Open the _Engineering_ group we created earlier, scroll to the _Members_ section (be careful to not accidentally do this in the _Members OF_ section), and click _Add..._

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/35.png)

Enter `john` into the dialog, click on _Check Names_, and then _OK_. Then click _OK_ to save the Engineering group members.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/36.png)

Repeat this for both the _Executive Leadership_ group and the _Sales_ group.

Add **Jane Doe** into **Sales** and **Susan Langford** into **Executive Leadership**

**Step 7 - Adjust auditing permissions on the rest of the shares:** 

Back in Windows Explorer, open up the properties of the _Engineering_ folder, go to the _Security_ tab and choose _Advanced_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/37.png)

Go the _Auditing_ tab (and click on _Continue_ if needed), then choose _Add_ at the bottom.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/38.png)

Click on _Select a principal_ and then enter `everyone` in the box, and click _Check Names_ and then _OK_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/39.png)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/40.png)

Set the options as follows: - **Type:** _All_ - **Applies to:** _This folder, subfolders and files_ - **Basic permissions:** _Modify_, _Read & execute_, _List folder contents_, _Read_, and _Write_ are checked

Click _OK_ here, and on all remaining dialog boxes

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/41.png)

Repeat those steps for the _Sales_ folder and _Executive Leadership_

**Step 8 - Access some files, and check the Windows Event Logs:** - 

Navigate through a couple of the folders and open up some files.

Go ahead and create a new file as well in any of those folders inside _C:\File Shares_, but not directly in the File Shares folder. After you've created it, edit it, and the delete it.

Which files you open, or where you create a new file doesn't matter, as long as it is inside one of the subfolders in _C:\File Shares_

After you've finished that, open up the _Windows Event Viewer_ and navigate to the _Security_ logs. You might want to click on _Refresh_ on the right to ensure that current logs are displayed

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/42.png)

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/43.png)

Look through the individual events listed, paying specific attention to **_Event ID 4663_**
OR 
Just create a **Filtering Rule** on this **Current Log** with Events:
- *EventID=4663  

![[Pasted image 20251110114747.png]]

Look for entries for the folders or files that you opened, especially ones that show _ReadData (or ListDirectory)_

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/45.png)

If you created and then deleted a file, you should also see an entry that shows _DELETE_ in the request information.

![Content Image](https://assets.ine.com/content/ptp/BrianOlliff/VOD-5229/LAB-3912/46.png)

Feel free to continue manipulating files and checking the events, or even adjust additional permissions to see what their effects may be.