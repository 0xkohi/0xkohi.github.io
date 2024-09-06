---
author:
  name: "kohi"
date: 2024-09-02
linktitle: TailsOS - retrieving files from Persistent Storage
type:
- post
- posts
title: TailsOS - retrieving files from Persistent Storage
weight: 5
series:
- Findings
---

## Context

With some friends we were doing a CTF for uni and I was making forensics challenges. I thought about doing one with an hardware components so people would find it more realistic. I ended up looking for a live OS that we could break and found TailsOS. There was a story linking this challenge with many others that I won't tell entirely here, but basically players were given the role of an analyst and a USB key (containing tailsOS) to retrieve information from another person (in persistent storage), to continue with OSINT.

## Verification

Before confirming the challenge, I had to make sure it is possible to retrieve a file in the persistant storage without the password on your local workstation.

## TailsOS

Let's talk a bit about TailsOS in itself. It is a live OS that you can install on a USB key. You can access it by booting your computer on this device. This OS is usually used for privacy purpose as they protect against surveillance, cencorship and viruses.

Each files/folders that you create on this OS will be removed after restarting, except in the folder "Persistant Storage", which can be created when first launching the OS.
Or accessed by entering a passphrase at launch time too. For more information you can read their website : https://tails.net/index.en.html
![image](/images/tails7.jpg)

Concerning what interests us, we can read on their website that LUKS is used as encryption method for the persistant storage, which means that we will need find a way to break it.

## Extraction of the encrypted partition

First we will need to list the different partitions and find our USB.
![image](/images/tails1.png)

We see here that our device contains 2 partitions : sdb1 and sdb2. 
After mounting the first partition, we see that it contains the following
![image](/images/tails2.png)

Looking at the all folders and especially the Live folder, we find a squashfs partition but nothing interesting.
![image](/images/tails3.png)

So the persistant folder is in the second partition, let's mount it and see what's inside
![image](/images/tails4.png)


## Breaking the LUKS volume

We can understand that the persistant folder is in this partition because it's encrypted with crypto_LUKS as said on the TailsOS website.
One of our option here is to bruteforce, of course this is the easiest one, but we decided to do that for our challenge. However, there is a slight issue if someone try using hashcat, as of now they only support LUKSv1 bruteforcing, here TailsOS uses LUKSv2. To break it, we can use a tool called "bruteforce-luks", which is working as follows
![image](/images/tails5.png)

Of course in our context, the human factor is the main problem since we just bruteforce the password. We did put a weak one for the challenge but TailsOS recommend using passphrase instead of password to prevent bruteforcing.

## Retrieving the text file

Now that we found the password, we can click the USB KEY in the file explorer and look for our file.
![image](/images/tails6.png)

We did put some information here to continue the challenge...(removed for this post)

## Conclusion

The post is not to show that TailsOS's persistant storage is breakable with bruteforcing since this is only based on the human factor choosing a weak password, it is more like a fun way to hide some information for challenges or a way to access data if you lost your password.
