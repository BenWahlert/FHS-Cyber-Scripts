**Before applying any remediation to a system please review all of the settings prior to depolying them.  If you need to modify settings to fit your environment please import these GPO's into GPMC and modify them as you need.**

To Apply Level 1 settings:
Apply Computer L1 and User L1

To Apply Level 2 Settings:
Apply Computer L1 & L2 and User L1 & L2

To Apply Bitlocker Settings:
Apply Bitlocker + Computer and Users GPOs

To import these settings into Active Directory, perform the following:

1) Unzip the GPO of your choice to a local folder on the computer you plan to import from.
2) Run gpmc.msc on the computer
3) Go to the Group Policy Object and/or create a new Group Policy Object
4) Right click on the selected Group Policy Object and click on "import settings"
5) Click Next
6) Click Next
7) Click Browse and select the folder that is holding the CIS GPO
8) Click Next
9) Click Next
10) Click finish, at this point the GPO should be imported into




To implement these settings on a standalone computer:

**Please make sure you modify these settings to fit your environment before applying on a local system**

Microsoft offers a tool to assit in applying these settings.  Please ensure you backup the local Security Policy before applying the full GPO. 

perform the following:
Download and Install the LGPO program developed by Microsoft. https://blogs.technet.microsoft.com/secguide/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0/





