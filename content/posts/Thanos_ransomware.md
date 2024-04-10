---
author:
  name: "malwr101"
date: 2024-04-08
linktitle: Thanos ransomware analysis
type:
- post
- posts
title: Thanos ransomware analysis
weight: 10
series:
- Malware analysis
---


## Context

We executed Thanos Ransomware on a VM to analyze its behavior and to better understand how general ransomware works. 
We decided to choose this one because most of the others can adapt themselves to a sandbox environment and so are not executing properly. Thanos Ransomware is also able to do it but since it is a ransomware-as-a-service, I found a sample in which the “Anti-VM” option was not enabled. 

## Malware execution

. . . Executing the binary
![coucou](/images/malwr1.png)

First thing appearing is this big info box/pop up giving us the instruction to follow to decrypt our files.

I noticed that all our files were not instantly encrypted, it took some time for the entire system.
By trying to restart the VM (not recommended to do in a real case scenario), this window information
screen before the password part appears.
![coucou](/images/malwr4.png)

When looking more in detail at the encrypted files, we can see that it targets the whole C:\ local disk
and around 5k of our files have been encrypted (on a new VM).
## Binary analysis
### Information

To start our analysis, we went for some reversing. First, we tried to open the initial binary with IDA
pro, but we realized it is a .NET framework:
![coucou](/images/malwr2.png)

Instead, we went for dnSpy which is a reversing tool made for .NET so more adapted to our case.
After opening it, we can already see some interesting class names. We will investigate some of them
and follow the main class to understand when and why each of this class are called:
![coucou](/images/malwr3.png)

We found out that the main class is called ”Program”. In this same class we can find the configuration
file “.cctor” which is different for each sample and contains the options selected or not for the
ransomware.
![coucou](/images/malwr6.png)

We see in this file that the “AntiVM” option is not activated so it explains why the ransomware
executed itself properly in our environment.
Let’s start to follow the main program

### Stage 1: Defense mechanisms

We see in the first place that the ransomware uses a function called “HookApplication” with processes
as parameters to write malicious code in the memory of the targeted processes.
The processes name is written in base64:
![coucou](/images/malwr7.png)

Right after, a PowerShell Cmdlet is executed, which deactivates the access control to the Windows
Defender folder. This can be a way for the malware to bypass this antivirus and allow malicious
processes to run.
![coucou](/images/malwr9.png)

![coucou](/images/malwr12.png)

Then, we see a couple of defensive classes that are called, let’s try to understand how they work.

• AntiKill

In this class, there is a function called “IamInmortal” in which the process handle of the current
process running is taken. Then the second method retrieves the security descriptor associated
with the process. On the third line, the DACL is used to specify the access control entries. InsertAce
allows you to insert this entry at the specified index of the DACL. CommonAce is the value of the
common access control entry applied and the parameters are set to deny the process of being
killed.

And at the end, the last method is used to set the security descriptor for the specified process
handle.

So, in short, this function modifies the security descriptor of the current process to grant specific
access rights to a user or group, to prevent the process from being killed or terminated.
![coucou](/images/malwr14.png)

Now by looking at the main function of the binary, we see that the function is called only once and this
way:
![coucou](/images/malwr15.png)

If the process is admin (role 544), then the two AntiKill functions will be executed:
![coucou](/images/malwr16.png)

The first prevent from launching the task manager and the second one from killing it as we just saw.

• Anti_Analysis

It can also detect its environment with the anti_analysis class and more precisely with the
RunAntiAnalysis function that calls some other functions to detect the manufacturer, the debugger
the size of the disk, … to determine if the binary is executed in a VM:
![coucou](/images/malwr17.png)

We notice that a function called “CleanMyStuff” is being used 3 times in the main program, by looking
at it (as its name says it), the ransomware uses this function to clear its traces.
![coucou](/images/malwr18.png)

First, it calls the function “ProcessCommand” to execute the following command line in with the cmd
process:
![coucou](/images/malwr19.png)

It starts with 3 ICMP packets echo request to 127.0.0.7 (could be used to add a delay), and then the
command uses the fsutil utility to set a file data area to zero. It defines a file data area from offset 0
with a length of 524288 bytes (or 512 KB). Regarding the hex characters, we can see on cyberchef.io
that they represent “” :
![coucou](/images/malwr20.png)

And inside of it we find the variable “$s”, which could most likely be a path to a file. The command
ends by deleting what contains this same variable.

About the second string encoded in base64:
![coucou](/images/malwr21.png)

This is also a PowerShell command; it will open a pop-up window for 3 seconds asking for user choices
(Y or N) to delete something that is not defined, it would most likely be a file path.

Here is how the CleanMyStuff() function is called inside the main function:
![coucou](/images/malwr22.png)

We see that in addition there is a command line: Process.GetCurrentProcess().Kill(), that basically kills
the process running.

Thereafter, following the main function, the following processes are executed:
Net.exe, sc.exe, taskkill.exe, vssadmin.exe, del.exe

### Stage 2: Encryption

As a first step, a random string of a defined length is declared as a dynamic pass, this string is then
encrypted with a function called Encrypt ():
![coucou](/images/malwr23.png)


This function encrypts a string by using a public key and the size of the key recovered with keySize and
publicKeyXml. Then it returns the result of the encryptoin converted in base64.

We have a list of files extensions that are targeted and encrypted with the” Crypt” function. After
doing some verification on conditions, this same function uses another function called
”WorkerCrypter” who is responsible for encrypting all the files with the extensions listed, with some
parameters:
![coucou](/images/malwr24.png)

In each folder path that has been encrypted by the function, a text file with the instructions to decrypt
the data is created.
![coucou](/images/malwr25.png)

![coucou](/images/malwr26.png)

This text file is created on the desktop at the same time.

### Stage 3: Data exfiltration

The ransomware then extracts some data via FTP with the following code:
![coucou](/images/malwr27.png)

It creates a new Web Client instance with the victim’s IP address recovered from a website:
![coucou](/images/malwr28.png)

By looking at the website on VirusTotal, we see that it is hosting some malicious files.
https://www.virustotal.com/graph/embed/ge9bc64b0337e4c1da10c9de8124dc89c3283505d8a7e454cb780320244e88205

The data extracted include:
 - The client unique identifier key
 - The date of encryption
 - The number of files that were processed.
 - The client IP address

In the sample we analyzed, it does not look like the encrypted files are being transferred to another
domain/website. Only some information about the victim is extracted.

### Stage 4: Covering traces

During the analysis we realized that the binary was not on the system anymore, after looking at its
executed commands we found this one:
![coucou](/images/malwr39.png)

Here the binary executes the command: cmd.exe /C choice /C Y /N /D Y /T 3 & Del. As we described
before in the analysis, the process deletes itself after answering the prompt automatically.
We can also see that this command is in the function “CleanMyStuff” used to cover its traces:
![coucou](/images/malwr18.png)

![coucou](/images/malwr19.png)

![coucou](/images/malwr21.png)

Detailed command:
 - ping 127.0.0.7 -n 3 > Nul: This command uses the ping utility to send three packets to the local IP
address 127.0.0.7. The -n 3 option specifies sending three packets. > Null redirects the output
(normally displayed in the console) to Null, which means that the output of the ping command will not
be displayed.

  - fsutil file setZeroData offset=0 length=524288 "%s": This command uses the fsutil utility to set data
to zero in a file specified by "%s". This means that the first 524,288 bytes (or 512 KB) of the file will be
filled with zeros. %s is a variable substitution which will be replaced by the file path.

  - Del /f /q "%s": This command deletes the file specified by "%s". The /f and /q options tell the Del
command to delete the file without asking the user for confirmation.

So, this sequence of commands sends three ping packets to the local IP address, then fills the first 512
KB of a specified file with zeros, and finally deletes that file.

  - Cmd /C: causes a command window to appear and run the command specified. It then causes the
window to close automatically.

  - Choice /C Y /N /D Y /T : displays an empty, flashing prompt. However, the /T 3 means that the prompt
will automatically select the default choice Y (/D Y) after 3 seconds

### Other interesting functions

Since the ransomware includes lots of functions that were not used, I still wanted to look at some of
them and understand what it can really do if they are activated.

There is a class called “rootkit” and by looking at it we understand that it downloads a file from the
following URL:
![coucou](/images/malwr29.png)

![coucou](/images/malwr30.png)

This URL downloads the raw code of another binary named ProcessHide64, available on GitHub. From
the README file of the repository, this program permits to “Hide any process from any monitoring tool
that uses NTQuerySystemInformation”. We can see that the developers of the malware made efforts
to hide their traces and are trying to slow the analysis process.

In the same block of code, the malware clears the recycle bin with the following cmd command:
![coucou](/images/malwr31.png)

Now let’s look at the network related functions, the program only uses one network function:
![coucou](/images/malwr32.png)

This function is used at the beginning of the program which makes sense because the discovery is
important for the next steps, if we take a closer look at the run function of the class network Spreading:

  - NetworkSpreading

The malware here does some network spreading when we look at the functions within it:
![coucou](/images/malwr33.png)

We see that it downloads a tool:
![coucou](/images/malwr34.png)

The URI was encoded in base64 so here it is in clear:
![coucou](/images/malwr35.png)

This binary does not seem to be downloadable from this URI anymore, but on the website, we can see
that PowerAdmin is a software used for Server Monitoring.

In the same function, the ransomware takes the network information of the local machine as followed:
![coucou](/images/malwr36.png)

So, it retrieves the IP address and the DNS entries.

Something else interesting is in the run function:
![coucou](/images/malwr37.png)

wmic.exe can be used to add exclusion and authorize malicious programs. Net.exe can be used to
retrieve information about the network or even create connections.
In this case, the malware is trying to connect to other machines of the same local network and if there
is a successful connection (with the password specified) then the malware will copy itself to the
connected machine and execute the file. As the name of the class says, it is network spreading.

![coucou](/images/malwr38.png)

Regarding the last if () condition above, it tries different methods to connect to the machine, first it
checks if there are credentials activated. If it is the case, then try the username “efadmin” in the group
EDENFIELD with the password “P455w0rd”. But if there are no credentials, it will only use the other
options, which are used as follow:

 -d: delete
 -f: force
 -h: help
 -s: target
 -n 2: number of repetitions
 -c: specify a path or a command to execute

## VISUAL-Procmon analysis

Now that we have explored the binary, it is time to look at how our VM environment is impacted and
compare what we see with our previous analysis.<br><br>

In the first place, I will download the logs that procmon displays us in a CSV format to send them to
another tool called VISION-Procmon which offers a better view and filters to focus on a specific process
which is helpful for malware analysis use cases.

In the process list we see mshta.exe, I decided to start with this one because I saw there were .hta files
in our system that appeared with the ransomware. By selecting it with VISION-procmon, and choosing
the filter “File operations” here is the graph that we obtain:
![coucou](/images/malwr5.png)

For more information on the process itself, mshta.exe is used to execute .hta files (HTML document)
on the web. It can be used to execute malicious scripts or install malicious software, as it can bypass
local Internet security settings because they are considered as trusted applications.

So, the long name on the right is the ransomware binary, we see with the first link that it is the parent
process of mshta.exe. Then, in the bottom right box, we can see the command that has been executed
and we see that the file “HOW_TO_DECYPHER_FILES.hta” has been executed.

We still have the .hta file on the desktop, and by executing it, we see that this corresponds to the first
big red box that we saw when executing the ransomware.

For the next process, we select cmd.exe and we stay with the “File operations” filter. As we saw during
the binary analysis in the covering track's part, the command line is executed but we had an unknown
path. Well here the file that is being deleted is the malware itself, so we understand that the function
CleanMyStuff has been used here.
![coucou](/images/malwr8.png)

There were no more interesting things to see here with VISUAL-procmon that we did not figure out
yet, but in the need to a report, this tool is great to make graph and quickly understand what happen
and how each process is executed and the parameters.

## Conclusion

As a first malware analysis, Thanos ransomware is interesting, I would say the obfuscation was not
really an issue, but it was still challenging to follow the main program and understand each function.

Since all the classes and options of configuration were not used in this sample, I mostly focused on the
ones called in the main program. Which means that I might have missed some information or not
detailed enough in some classes that were outside of the box.

I have not focused on the decryption possibilities, but it is something that could be interesting to
do in the future