---
author:
  name: "kohi"
date: 2025-05-01
linktitle: Prometei - Static and dynamic analysis
type:
- post
- posts
title: Prometei - Static and dynamic analysis
weight: 10
series:
- Malware analysis
---


## Contexte

Sample at : https://bazaar.abuse.ch/sample/8cfe4b3888c08ead3574701b20d70bbbbf86b79faeb2fde1d072e090f56d60e5/

Usually I mostly focus on Windows malwares, but I wanted to try looking at a Linux one. So I went for the first ELF sample that I saw on Malwarebazaar, and it is a crypto miner called Prometei. 

My goal here is to find somes IoCs in order to write a Yara rule and be able to detect it, I will not go into too much details on the reverse part, sorry in advance.

##  Static Analysis
### Unpacking 

With Detect It Easy (die.exe) we can notice that our file is packed using UPX, which is pretty common. We also see that there is a "superposition" at the end of the file corresponding to the footer of the elf.
![die_result](/images/prometei-23.png)

I extracted the footer with binwalk and it contains an encryption key and an ID used by the malware :
![string_command_config](/images/prometei-7.png)

Packers are used by malware developpers to hide their code and make it more complicated for people to analyse them.
For UPX, there is a linux tool as command line that we can use to unpack the binary and retrieve the source code.
![upx_command](/images/prometei-10.png)

The command did not work as expected, it is possible that either an UPX variant is used or the UPX format has been modified on purpose (headers modification).

UPX headers contain specific fields that have to be present such as "l_magic", "p_filesize" and "p_blocksize" in order to be unpacked by the default UPX CLI. There is a blog from the JPCERT (https://blogs.jpcert.or.jp/en/2022/03/anti_upx_unpack.html) that helped me better understand how exactly they work and what could be modified by malware developpers to prevent unpacking.

I used a tool on GitHub : https://github.com/lcashdol/UPX in order to repair the UPX header, in case they were modified intentionnaly by the malware developpers.

The result I got tells me that the headers are apparently not the issue : 
![header_check_upx](/images/prometei-24.png)

I tried to unpack it manually with r2 by setting a breakpoint on the first munmap syscall, that we can obtain with strace and then dump the rest of the ELF but it did not work as well. 

I lost too much time on that, and decided to check if anything was wrong again in the header. I saw that usually the 'p_filesize' bits are doubled, but it was not the case here so I modified the hex bits with HxD as follow : 
![HxD_1](/images/prometei-25.png)
![HxD_2](/images/prometei-26.png)

I tried again to unpack it with the 'upx -d' CLI but it still did not work, so I looked at the footer and remembered the "superposition" that was indicated in Detect It Easy.
![HxD_3](/images/prometei-27.png)

We can see here that the UPX footer seems right, and the "superposition" is the json part. I removed it and tried to unpack again and it worked !

I suppose that when UPX tries to unpack a binary, it checks the footer and it probably saw this superpositon part and didn't took it has a real footer. It would also explain why the tool to repair UPX headers did not work, because
they were able to find the right header and footer bytes. 
At least having this issue helped me better understand how UPX works.

If we open it again with Detect It Easy, we are now able to see the Compiler, the and the language of the source code.
![die_2](/images/prometei-28.png)

### Researching IoCs

Now that we have our sample unpacked, we can try different things to understand how it works. 
Let's start with the classic strings command. Here I used a mandiant tool called flarestrings, which is composed of two scripts flarestrings and rank_strings. The second one allows us to rank all the strings of a binary from what appears to be malicous to non-malicious based on machine learning model. The strings appearing first by using this script are the following : 
![flarestrings_result](/images/prometei-30.png)

By searching for IP addresses, I found some URLs :
![IoC1_strings](/images/prometei-20.png)

The first one is flagged  as malicious on VirusTotal (VT) but nothing appears when I browse it.
The second and third one do not seem to exist anymore.
The last one is a bit more interesting, you can see at the end 'b32.i2p' which means that the malwares uses I2P (Invisible Internet Project), an 'anonymous' network that allows you to hide communications and on which you can host websites or services.

It is written 'b32' so it means that the address is encoded in base32.
We can see at the end that a file is written '/prometei.cgi', which corresponds to the sample we are analysing.

Next, we see that a process called "updatecheckerd" is getting killed, something to investigate later.
![IoC2_strings](/images/prometei-21.png)

I also found some strings related to crontab, maybe about persistence, something to investigate.
![IoC3_persistence](/images/prometei-22.png)

Now we can open it in a disassembler (I used IDAv7 PRO here) to better understand how functions are working together.
We see that there are around 1000 functions.
I took some time to go through most of them and rename the ones I was interested in. Thanks to the strings observation done before, I started by searching for the strings occurrence and lookup the functions.

URL and communication Functions :
Starting with the URLs that we found, I found in .rodata the URLs and jumped on the first function using them, after some reversing it looks like that : 
![IDA_1](/images/prometei-31.png)

This function, starts by checking if the file /etc/pcc1 exists, if so, it reads its content and then copies it into memory with (&qword_BEA400). If not, it copies the url : http://dummy.zero/cgi-bin/prometei.cgi into memory, which is most likely a decoy.

So in short, this function does a C2's conditional redirection behaviour, it selects a different URL depending on the presence of /etc/pcc1. I do not know what pcc1 is yet, it could be a flag of a sandbox or a way to check if the host is already existed. I will investigate it later during the dynamic analysis.

Now if we take a look at the last two URLs and the function related, we can see some interesting strings : 
- &i=%s&enckey=%s&answ=%s  
- "?&i=%s&answ=OK" 
- "?&i=%s&r=%d"
- "&answ=%s"

What I understood here is that the function formats HTTP requests with dynamic parameters, probably deals with C2 responses, generates an HTTP "200 OK" itself. And uses an encryption key. I will try figuring it more in details during the dynamic analysis by following the network traffic. 

Key functions : 
I checked for other strings linked to encryption keys and found another function that is using it as well, here is how it looks after analysis :
![IDA_2](/images/prometei-32.png)

From what I understood, this function verifies if something (most likely a key) is present in the buffer "qword_BEA400" and it then generates an URL with an ID and an Enckey.
Afterwards, it sends the HTTP request and if the value "64" is returned, it does some other actions.

I remembered here that in the footer of the main binary (before unpacking it) there was a json configuration : 
{"config":1,"id":"2fUXR0axaNBdA2c7","enckey":"FqVSMYZkxrPc7BUz4RU3lhCdQ1694GUjaZ4HlVrbFz+Lfd5MebkRBJijqZWXCGtKoWsQpHT+hcYwbjTgiTz6A56MsyScYt+BYEa5rjRckD30YFYDXIGTWc0kd+6m+WhRPdiWjgKlZy8YqEF3nUIcFFCtHwshuwKWn9up+Q2wCjw="}

It means that the malware embeds a configuration with an enckey value. What we can get out of this base64 key is its lenght : 129 bytes after being decoded. 
In the function we just analysed, we saw that the variable 'enckey' was dynamically generateed in qword_BE9B40, so it is possible that the json configuration is loaded at runtime and injected to the variables qword_BE9B40 and id (if the composition is a Key + an IV).

So basically this function retrieves the value of the json configuration in the buffer "qword_BEA400", modifies the initial base64 by changing the + to - and the = to _ in the function that i renamed "b64_operation" and then integrates in into an URL.

Process functions : 
The next function I was interested in is the one containing strings of processes, it could be interesting to see what are the process created and what are they used for. I will not spend too much time reversing this one as I prefer looking at them during the dynamic analysis. Here is the list of the different process that I will try following later :
- pdefenderd
- walker
- netwalker
- netsync
- nvsync

Persistence function :
A crucial step in most of malwares is the persistence.
During the analysis of the process functions, I also tried to understand what the binary uplugplay is, and I found an interesting function that was processing this other binary, here are the interesting parts :
![IDA_3](/images/prometei-33.png)

Here the first thing done is clearing byte_537080. Then it is compared with the path "/etc/uplugplay" and "/usr/sbin/uplugplay". There is a check if the process are already running. 
Following this, there is a creation of systemd files with the fields :
[Unit]
Description=UPlugPlay
After=multi-user.target
[Service]
Type=forking
ExecStart=/usr/sbin/uplugplay OR /etc/uplugplay
[Install]
WantedBy=multi-user.target

This file is saved in "/lib/systemd/system/uplugplay.service".
Multiple systemd commands are executed :
- systemctl stop uplugplay.service
- systemctl daemon-reload
- systemctl enable uplugplay.service
- systemctl start uplugplay.service

At the end, the function waits for 23secs for "unk_536A40" to be accessible, if so "OK" is printed, if not "Fail!!!" is printed.

So what we can understand from this function is that the content of the buffer "qword_BEA400" is copied in a temporary buffer "byte_537080" and this buffer is then wrttien in uplugplay in /usr/sbin or /etc/. 
![IDA_4](/images/prometei-34.png)

It is a persistence mechanism by memory injection that installed itself with a systemd service, starts at launch and verify its execution. This file is set executable with "chmod 777" and starts automatically with "systemctl start uplugplay.service". 

I will try during the dynamic analysis to find more information on the code in uplugplay.

I saw at the beginning some occurrence of crontab, I wanted to take a look to see if it was related to the persistence we just saw.
![IDA_5](/images/prometei-37.png)

In this function, we see that a cron task is created "task.cron" set to be executed at each reboot. Then the path of a file is added "byte_1573A80", probably uplugplay.

The current crontab is retrieved with "crontab -l" and a job research is done. If "no crontab" it creates a new entry, else, it does not insert a second one.
There is a writing operation in the temporary file "task.cron" and its installation with "system("crontab task.cron")". Following this, the temporary file is deleted "delete_file("task.cron")".
![IDA_6](/images/prometei-36.png)

To find "crontab task.cron", we see that the variable concatenates crontab with &v19[9] which is the start of 'task.cron' since in v19 we already have :  
- 0-7 : @reboot
- 8 : '\0'
- 9 : task.cron

We see that it's pretty clean, it prevents itself from having multiple cron tasks and deletes the temporary file.

Mining functions : 
Since we are dealing with a crypto miner, there are obviously functions related to this activity. By following the strings "start_mining" and "stop_mining", I jumped on the function using them. The first one is analysing multiple commands as strings and perform actions depending on what they contain.
![IDA_7](/images/prometei-38.png)

This acts as a command interpreter of C2 servers. So it first accepts the command "start_mining" and then
- Downloads a binary with wget
- Is able to copy, clear or verify files with fcopy and fdel
- Can execute it with exec
- Calculate a hash with fchk
- And finally encode a structured answer in qword_1573E80

The command "start_mining" is controlled by a second function that we can call "mining_controller" that : 
- Verifies if the process "updatecheckerd" is running with pidof
- Initiates buffers
- construct a command (v4)
- Kills the old process running if it exists with "pkill updatecheckerd"
- Start the process with the command (v4)

If we take a look at the command "stop_mining", its goal is to kill the process "updatecheckerd" with pkill.

Another thing that I found is that the buffer qword_BE9D40 seems to contain interesting information, I found the variable that saves the json configuration in the buffer: qword_BEA400 and in which function the key is used : sub_409F4D. I will try to retrieve the content of qword_BE9D40 during the dynamic analysis.

### How the malware works

From what I understood during the reverse part, the malware works as follow :

1. Retrieving information of its host
    - Get OS information by trying to execute the commands : '/etc/os-release', '/etc/redhat-release', '/etc/debian-version'
    - Get processor information by trying to execute the commands : '/proc/cpuinfo', '/proc/meminfo', 'hostnamectl', 'uptime' and it then writes these information in a form format : 'Product name:', 'Hardware model:', 'Virtualization:', 'Hardware Vendor:', 'MemTotal:', 'model name:'
    - Get network information with the commands : 'CommId', 'nslookup 8.8.8.8'

2. Connects to the C2 either with the .onion or .i2p URL or a dummy one

3. Accepts the C2 commands (start_mining, stop_mining, exec, quit, ...)

4. If start_mining is received : 
    - wget updatecheckerd and executes it with "system" or "exec"

4. Persistence 
    - With the file uplugplay in /usr/sbin/uplugplay or /etc/uplugplay
    - Creation of a systemd service uplugplay.service
    - Creation of a cron task containing "@reboot /usr/sbin/uplugplay"

5. Hiding itself by controlling the processes with pkill and pidof

## Dynamic Analysis 
### Context and setup
Let's now try to analyse the malware dynamically to see if it works as expected and if we can understand more things on its behaviour.

I used Lauri Wired's lab which works on docker : https://github.com/LaurieWired/linux_malware_analysis_container thank you for that !

The setup I have is a local ubuntu VM on which I connect through SSH and launch the script which creates a docker container where I can manipulate the malware. This allows me to execute the malware and just start a new docker container whenever I want.

### Follow our findings

First let's just execute the malware without arguments : 
![mal_execution_1](/images/prometei-11.png)

So we have couple errors, the first one tells us that the malware cannot operate because it has not been booted with systemd. Indeed it is the case because we are inside a docker container, this could be a protection against malware analysis (like anti-vm, anti-sandboxes, ...)
The second error is more specific, it says that a Host is down. It happens because the socket D-Bus that the malware tries to use does not exist in this environment.

What we can do here is look at the system calls made by the malware.
The command 'strace' allows us to do it with several parameters : "strace -ff -o strace.out.log ./prometei.elf"
We can observe some logs in the terminal, there are again systemd errors because we are not in a systemd environment (docker) but we have the creation of a symlink with the installation of the systemctl service uplugplay, which is something we identified earlier in the static analysis :
![strace1](/images/prometei-39.png)

We can check its configuration, and it is the same one that we observed in the static analysis :
![strace2](/images/prometei-41.png)

I also got multiple files created as output, the 'task.cron' contains something we also saw before : 
![strace3](/images/prometei-40.png)

In all the other log files, there are mostly system calls, I will not spend too much time checking them, it basically tries to access system files
![strace_1](/images/prometei-13.png)
![strace_2](/images/prometei-16.png)

This actually allows the malware to retrieve its own execution path. (which could be used for future actions)
We observe some memory mapping and memory protection too.
![strace3](/images/prometei-17.png)

Then, the malware tries to access several files in read-only, and '/etc/hosts' in write. We don't know why exactly why but it might be a check that they exist and add some lines in /etc/hosts.
![strace4](/images/prometei-14.png)

At the end, the malware tries to access the file '/usr/sbin/uplugplay', which shows us where it was installed because with the static analysis we had a doubt between '/usr/sbin/' and '/etc/'.
![strace5](/images/prometei-15.png)

We can retrieve the hash of the uplugplay file, as IoC : 
![strace6](/images/prometei-42.png)

There were too many systemd errors, so I executed it in a Virtual Machine instead in order to see more things on the processes and the network traffic.

By starting service.uplugplay with systemctl, we can follow its activity. Regarding the open ports, we see that uplugplay is listening on TCP port 89 and many other UDP ports.
![alt text](/images/prometei-43.png)

Now I can try communicating with it locally, I have a first terminal with tcpdump running, listening on port 89, and a second terminal sending the command we saw during the static analysis (start_mining, stop_mining, etc) with ncat. My first try was with start_mining and we see that it works pretty good :
![alt text](/images/prometei-44.png)

It looks like the json configuration we had in the binary, but there are some differences, "id" is now "i=" the value of "enckey" is different, and we have a new data : "answ" that was not present in the static analysis. 
It is more clear on wireshark:
![alt text](/images/prometei-45.png)

It is possible that a wallet or a pool is in the "answ" field but it looks like it is encrypted. Even after modifying the "-" by "+" and the "_" by "=" to retrieve the original b64.

I did not observe any of the process "updatecheckerd", "netwalker", "walker" being created on my host, it is possible that my lab blocks the execution of the malware at some point but they can still be considered as IoCs thanks to the static analysis.

## Conclusion

With the static and dynamic analysis performed of prometei, I was able to better understand the malware's behaviour and identify this list of IoCs:

1. The persistence file : uplugplay
2. The hash of uplugplay : sha1=4419a8accd996b8b6ec88a166d2263ea8ef5aa69
2. The cron task : task.cron (with @reboot)
3. The usage of the commands pgrep and pidof
5. The URLs : http://dummy.zero/cgi-bin/prometei.cgi, https://gb7ni5rgeexdcncj.onion/cgi-bin/prometei.cgi, http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin//prometei.cgi
6. The processes : updatecheckerd, netwalker, walker, nvsync, netsync


### Detection rule

With those IoCs, we are able to write a Yara rule that will help detect if Prometei is on your host/network.
```python
rule IoCs_Prometei
{
    meta:
        description = "Detects Prometei activities on your host"
        author = "kohi"
        date = "2025-05-01"
        malware_family = "Prometei"
        version = "1.0"
        hash = "8CFE4B3888C08EAD3574701B20D70BBBBF86B79FAEB2FDE1D072E090F56D60E5"
    strings:
        $bin1 = "uplugplay"
        $bin2 = "updatecheckerd"
        $proc1 = "netwalker"
        $proc2 = "walker"
        $proc3 = "nvsync"
        $proc4 = "netsync"
        $cron = "@reboot /usr/sbin/uplugplay -cron"
        $cronfile = "task.cron"
        $cmd1 = "pgrep"
        $cmd2 = "pidof"
        $url1 = "http://dummy.zero/cgi-bin//prometei.cgi"
        $url2 = "https://gb7ni5rgeexdcncj.onion/cgi-bin//prometei.cgi"
        $url3 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi"
    condition:
        (
            any of ($bin*) and
            any of ($proc*) and
            any of ($cmd*) and
            any of ($url*) and
            $cron
        ) or
        $cronfile
}
```
