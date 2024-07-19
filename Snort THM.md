# TryHackMe: Snort Writeup

The room: [How to use Snort to detect real-time threats, analyze recorded traffic files, and identify anomalies](https://tryhackme.com/room/snort)

## Task 1: Introduction

**SNORT** is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS). It was developed and is still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team. 

The official description: *"Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generate alerts for users."*



















## Task 2: Interactive Material and VM

### 2.1. Navigate to the Task-Exercises folder and locate the hidden file `.easy.sh`
**This module includes a VM with Snort installed and an artifical network traffic generator for us to use later on**
 
### Questions:
Navigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output
The output of running the command `sudo ./.easy.sh` is: Too Easy





















## Task 3: Introduction to IDS/IPS


**Intrusion Detection System (IDS)**

**IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event.**

### There are two main types of IDS systems;

Network Intrusion Detection System (NIDS) - NIDS monitors the traffic flow from various areas of the network. The aim is to investigate the traffic on the entire subnet. If a signature is identified, an alert is created.
Host-based Intrusion Detection System (HIDS) - HIDS monitors the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, an alert is created.

### Intrusion Prevention System (IPS)
IPS is an active protecting solution for preventing possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

### There are four main types of IPS systems;

Network Intrusion Prevention System (NIPS) - NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, the connection is terminated.
Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA) - Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, the connection is terminated.
Network Behaviour Analysis System works similar to NIPS. The difference between NIPS and Behaviour-based is; behaviour based systems require a training period (also known as "baselining") to learn the normal traffic and differentiate the malicious traffic and threats. This model provides more efficient results against new threats.
The system is trained to know the "normal" to detect "abnormal". The training period is crucial to avoid any false positives. In case of any security breach during the training period, the results will be highly problematic. Another critical point is to ensure that the system is well trained to recognise benign activities. 
Wireless Intrusion Prevention System (WIPS) - WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there. If a signature is identified, the connection is terminated.
Host-based Intrusion Prevention System (HIPS) - HIPS actively protects the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, the connection is terminated.
HIPS working mechanism is similar to HIDS. The difference between them is that while HIDS creates alerts for threats, HIPS stops the threats by terminating the connection.


Detection/Prevention Techniques

There are three main detection and prevention techniques used in IDS and IPS solutions;

Technique	Approach
Signature-Based

This technique relies on rules that identify the specific patterns of the known malicious behaviour. This model helps detect known threats. 
Behaviour-Based

This technique identifies new threats with new patterns that pass through signatures. The model compares the known/normal with unknown/abnormal behaviours. This model helps detect previously unknown or new threats.
Policy-Based	This technique compares detected activities with system configuration and security policies. This model helps detect policy violations.



### Capabilities of Snort;

- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support! (Linux & Windows)
- Snort has three main use models;
Sniffer Mode - Read IP packets and prompt them in the console application.
Packet Logger Mode - Log all IP packets (inbound and outbound) that visit the network.
- NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes - Log/drop the packets that are deemed as malicious according to the user-defined rules.**

## Task Questions

### 3.1. Which Snort mode can help you stop the threats on a local machine?
- **HIPS**

### 3.2. Which Snort mode can help you detect threats on a local network?
- **NIDS**

### 3.3. Which Snort mode can help you detect the threats on a local machine?
- **HIDS**

### 3.4. Which Snort mode can help you stop the threats on a local network?
- **NIPS**

### 3.5. Which Snort mode works similar to NIPS mode?
- **NBA**

### 3.6. According to the official description of Snort, what kind of NIPS is it?
- **Full-blown**

### 3.7. NBA training period is also known as …
- **Baselining**




























## Task 4: First Interaction with Snort
**We will now verify snort is downloaded and its configuration file**
| Parameter | Description                                                                                   |
|-----------|-----------------------------------------------------------------------------------------------|
| -V / --version | This parameter provides information about your instance version.                         |
| -c        | Identifying the configuration file                                                             |
| -T        | Snort's self-test parameter, you can test your setup with this parameter.                      |
| -q        | Quiet mode prevents Snort from displaying the default banner and initial information about your setup. |



## Task Questions

### 4.1. Run the Snort instance and check the build number.
- **Build Number:** 149

### 4.2. Test the current instance with the `/etc/snort/snort.conf` file and check how many rules are loaded with the current build.
- **Rules Loaded:** 4151

### 4.3. Test the current instance with the `/etc/snort/snortv2.conf` file and check how many rules are loaded with the current build.
- **Rules Loaded:** 1






## Task 5: Sniffer Mode
**In this task we practices different sniffing techniques using the traffic generator and different parameters for example:**
### Let's run Snort in Sniffer Mode
- sudo snort -de
- sudo snort -d
- sudo snort -v
- sudo snort -X


- `-v` : Verbose. Display the TCP/IP output in the console.
- `-d` : Display the packet data (payload).
- `-e` : Display the link-layer (TCP/IP/UDP/ICMP) headers.
- `-X` : Display the full packet details in HEX.
- `-i` : Define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff.

Note that you can use the parameters both in combined and separated forms as follows:

- `snort -v`
- `snort -vd`
- `snort -de`
- `snort -v -d -e`
- `snort -X`

**Questions and answers:** N/A













## Task 6: Operation Mode 2: Packet Logger Mode
**In this task we used the traffic and practices inspecting various logs for example:** 
- sudo snort -dev -K ASCII
- sudo snort -r snort.log.1638459842
- sudo tcpdump -r snort.log.1638459842 -ntc 10
- sudo snort -r logname.log -X
- sudo snort -r logname.log icmp
- sudo snort -r logname.log tcp
- sudo snort -r logname.log 'udp and port 53'

## Task Questions

### 6.1. Navigate to the folder `145.254.160.237`. What is the source port used to connect to port 53?
- **Source Port:** 3009

### 6.2. Use `snort.log.1640048004` 
Read the `snort.log` file with Snort; what is the IP ID of the 10th packet?
- **IP ID of 10th Packet:** 49313

### 6.3. Read the `snort.log.1640048004` file with Snort; what is the referer of the 4th packet?
- **Referer of 4th Packet:** [http://www.ethereal.com/development.html](http://www.ethereal.com/development.html)

### 6.4. Read the `snort.log.1640048004` file with Snort; what is the Ack number of the 8th packet?
- **Ack Number of 8th Packet:** 0x38AFFFF3

### 6.5. Read the `snort.log.1640048004` file with Snort; what is the number of the “TCP port 80” packets?
- **Number of TCP Port 80 Packets:** 41

















## Task 7: Operation Mode 3: IDS/IPS
### Snort in IDS/IPS Mode 
## NIDS Mode Parameters

| Parameter | Description                                                                                           |
|-----------|-------------------------------------------------------------------------------------------------------|
| -c        | Defining the configuration file                                                                       |
| -T        | Testing the configuration file                                                                        |
| -N        | Disable logging                                                                                      |
| -D        | Background mode                                                                                      |
| -A        | Alert modes:                                                                                         |
|           | - **full:** Full alert mode, providing all possible information about the alert. This is also the default mode; once you use `-A` and don't specify any mode, Snort uses this mode. |
|           | - **fast:** Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers. |
|           | - **console:** Provides fast style alerts on the console screen.                                      |
|           | - **cmg:** CMG style, basic header details with payload in hex and text format.                        |
|           | - **none:** Disabling alerting.                                                                       |




## Task Questions
### 7.1. What is the number of detected HTTP GET methods?
- **Number of Detected HTTP GET Methods:** 2






















## Task 8: Operation Mode 4: PCAP Investigation


## PCAP Mode Parameters

| Parameter                  | Description                                                 |
|----------------------------|-------------------------------------------------------------|
| -r / --pcap-single=        | Read a single pcap                                         |
| --pcap-list=""             | Read pcaps provided in command (space separated).         |
| --pcap-show                | Show pcap name on console during processing.              |

### Investigating Single PCAP with Parameter `-r`

For test purposes, you can still test the default reading option with pcap by using the following command:

```bash
snort -r icmp-test.pcap
```
```bash
sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10
```

## Task Questions

### 8.1. What is the number of generated alerts?
- **Number of Generated Alerts:** 170

### 8.2. How many TCP Segments are Queued?
- **Number of TCP Segments Queued:** 18

### 8.3. How many “HTTP response headers” were extracted?
- **Number of HTTP Response Headers Extracted:** 3

### 8.4. What is the number of generated alerts?
- **Number of Generated Alerts:** 68

### 8.5. What is the number of generated alerts?
- **Number of Generated Alerts:** 340

### 8.6. What is the number of detected TCP packets?
- **Number of Detected TCP Packets:** 82

### 8.7. What is the number of generated alerts?
- **Number of Generated Alerts:** 1020














## ask 9: Snort Rule Structure
## Action

There are several actions for rules. Make sure you understand the functionality and test it before creating rules for live systems. The most common actions are listed below:

| Action  | Description                                              |
|---------|----------------------------------------------------------|
| alert   | Generate an alert and log the packet.                   |
| log     | Log the packet.                                         |
| drop    | Block and log the packet.                              |
| reject  | Block the packet, log it, and terminate the packet session. |

## Protocol

The Protocol parameter identifies the type of the protocol that is filtered for the rule.

Note that Snort2 supports only four protocol filters in the rules: IP, TCP, UDP, and ICMP. However, you can detect application flows using port numbers and options. For instance, if you want to detect FTP traffic, you cannot use the FTP keyword in the protocol field but filter the FTP traffic by investigating TCP traffic on port 21.

## IP Filtering

| Description                        | Rule                                                                                                  |
|------------------------------------|-------------------------------------------------------------------------------------------------------|
| **Filter a Single IP Address**     | `alert icmp 192.168.1.56 any <> any any (msg: "ICMP Packet From "; sid: 100001; rev:1;)`              |
| **Filter an IP Range**             | `alert icmp 192.168.1.0/24 any <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`            |
| **Filter Multiple IP Ranges**      | `alert icmp [192.168.1.0/24, 10.1.1.0/24] any <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)` |
| **Exclude IP Addresses/Ranges**    | `alert icmp !192.168.1.0/24 any <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`            |

## Port Filtering

| Description                               | Rule                                                                                               |
|-------------------------------------------|----------------------------------------------------------------------------------------------------|
| **Filter a Specific Port**                | `alert tcp any any <> any 21 (msg: "FTP Port 21 Command Activity Detected"; sid: 100001; rev:1;)` |
| **Exclude a Specific Port**               | `alert tcp any any <> any !21 (msg: "Traffic Activity Without FTP Port 21 Command Channel"; sid: 100001; rev:1;)` |
| **Filter a Port Range (Type 1)**          | `alert tcp any any <> any 1:1024 (msg: "TCP 1-1024 System Port Activity"; sid: 100001; rev:1;)`  |
| **Filter a Port Range (Type 2)**          | `alert tcp any any <> any :1024 (msg: "TCP 0-1024 System Port Activity"; sid: 100001; rev:1;)`   |
| **Filter a Port Range (Type 3)**          | `alert tcp any any <> any 1025: (msg: "TCP Non-System Port Activity"; sid: 100001; rev:1;)`     |
| **Filter a Port Range (Type 4)**          | `alert tcp any any <> any [21,23] (msg: "FTP and Telnet Port 21-23 Activity Detected"; sid: 100001; rev:1;)` |


## Snort Rule Options

There are three main rule options in Snort:

1. **General Rule Options**: Fundamental rule options for Snort.
2. **Payload Rule Options**: Rule options that help investigate the payload data. These options are useful for detecting specific payload patterns.
3. **Non-Payload Rule Options**: Rule options that focus on non-payload data. These options help create specific patterns and identify network issues.

### General Rule Options

| Option       | Description                                                                                                  |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **Msg**      | The message field provides a basic prompt and quick identifier of the rule. It appears in the console or log when the rule is triggered, usually summarizing the event in a one-liner. |
| **Sid**      | Snort rule IDs (SID) must be unique and follow a predefined scope: `<100: Reserved rules`, `100-999,999: Rules from the build`, `>=1,000,000: Rules created by users`. Rules should have an SID greater than 100,000. SIDs should not overlap. |
| **Reference**| Each rule can include additional information or references to explain the rule's purpose or threat pattern. This could include Common Vulnerabilities and Exposures (CVE) IDs or external information, aiding in alert and incident investigation. |
| **Rev**      | The revision number indicates how many times the rule has been updated. Rules can be modified for performance and efficiency, and each rule should have a unique revision number. Analysts should keep their own rule history as there is no auto-backup feature. |

### Example Rule

```plaintext
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; rev:1;)
```






## Task Questions 
### 9.1. Write a rule to filter IP ID “35369” and run it against the given pcap file. What is the request name of the detected packet?

**alert icmp any any <> any any (msg:"IP ID"; id:35369; sid:1000001; rev:1;)**
**sudo snort -c local.rules -A full -l . -r task9.pcap**
*8sudo snort -r snort.log.1680681113**
#### TIMESTAMP REQUEST


### 9.2. Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?

alert tcp any any <> any any (msg: "FLAG TEST"; flags:S; sid: 100001; rev:1;)
#### 1





### 9.3. Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?

sudo rm snort.log.1680681590 snort.log.1680681113
sudo rm alert
alert tcp any any <> any any (msg: "FLAG TEST"; flags:PA; sid: 100001; rev:1;)
#### 216











### 9.4. Create a rule to filter packets with the same source and destination IP and run it against the given pcap file. What is the number of detected packets?

alert tcp any any <> any any (msg: "SAME-IP TEST"; sameip; sid: 100001; rev:1;)
alert udp any any <> any any (msg: "SAME-IP TEST"; sameip; sid: 100002; rev:1;)
#### 10







### 9.5. Case Example – An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?
#### rev












## Task 10: Snort2 Operation Logic: Points to Remember
### Points to Remember

Main Components of Snort

Packet Decoder - Packet collector component of Snort. It collects and prepares the packets for pre-processing. 
Pre-processors - A component that arranges and modifies the packets for the detection engine.
Detection Engine - The primary component that process, dissect and analyse the packets by applying the rules. 
Logging and Alerting - Log and alert generation component.
Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component. 
There are three types of rules available for snort

Community Rules - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
Registered Rules - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
Subscriber Rules (Paid) - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).








