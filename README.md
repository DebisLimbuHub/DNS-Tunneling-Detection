# DNS Tunneling Detection Engineering: Custom IDS Rules for Exfiltration
This project provides an out of the box solution for catching covert DNS tunneling used in data exfiltration and C2 channels, by combining multiple detection indicators within Suricata’s rule engine. It was developed to address the gap in real time DNS tunnel detection, enabling security teams to detect stealthy DNS abuse with minimal overhead using open source tools.

### Short Summary
- Engineered Suricata signatures in `local.rules` using PCRE matching and threshold logic to detect tunneling indicators in DNS telemetry
- Built Python traffic generators to reproduce tunneling patterns on demand, enabling deterministic validation of alert logic and tuning
- Ran dataset based evaluation and documented detection performance against a default IDS baseline using recall, precision and F1 score
- Operationalised alert output for SOC workflows by validating Suricata alerting in `fast.log` and event visibility in `eve.json`
- Demonstrated incident triage thinking by mapping alerts to attacker tradecraft such as encoded subdomains, burst DNS activity and randomised labels
- Delivered clear technical documentation that explains detection logic, deployment steps and limitations including encrypted DNS blind spots

## Overview
DNS Tunneling is a technique that encodes data or commands within DNS queries and responses, allowing attackers to smuggle information out of a network or establish command and control over DNS. Because DNS is critical and often lightly filtered, attackers can exploit it to exfiltrate data in small chunks (e.g. encoded in subdomain labels) or to issue backdoor commands, all while appearing as normal DNS traffic. Traditional detection methods and default IDS rulesets only catch obvious anomalies, such as huge DNS payloads or suspicious TTLs and often miss stealthy tunnels. This project tackles that challenge by integrating multiple DNS tunnel indicators into Suricata rules. The detection logic focuses on three key features observed in DNS based attacks:

- High entropy or unusually long domain names: Malicious queries often contain long, random-looking subdomains due to encoded data. For example, DNScat2 and Iodine generate subdomains that are much longer than typical benign queries.

- Suspicious query frequency/timing: Tunneling malware tends to send many queries in a short time or at very regular intervals to stream data. Normal users rarely perform hundreds of DNS lookups per minute to the same domain.

- Randomised subdomain patterns: Encoded data often produces strings with character distributions (hex, base32, lots of digits) that are not seen in human readable domains. For instance, a payload encoded in base32 yields a subdomain like `ABCDQXYZ2EF...` which stands out from legitimate names.

By combining these indicators, the custom rules can catch various tunneling methods, including those used by tools like Iodine, DNScat2 and dns2tcp in real time. The project was evaluated on multiple DNS traffic datasets, demonstrating significantly improved detection rates over default Suricata rules while maintaining low false positives. Sections below summarises the repository contents, detection logic for each rule, how to set up and use the system, example usage, key results from evaluations, limitations and future enhancements.

## Repository Contents

This repository includes the following components:

- Suricata Rules (`local.rules`): Three custom DNS tunneling detection rules and a combined variant written in Suricata’s rule syntax. Each rule targets one type of indicator:

1. High Entropy DNS Query Rule: Flags DNS queries with extremely long or random subdomains.

2. High Query Rate Rule: Flags a source that sends an unusually high volume of DNS queries in a short time.

3. Randomised Subdomain Rule: Flags DNS queries whose subdomain matches patterns of base32 or hexadecimal encoded data.

4. Combined Rule: Combination that enables all the above detections together.

- Traffic Generation Scripts: Python scripts to simulate DNS query patterns that would trigger each rule. These scripts generate synthetic DNS traffic for testing and demonstration:

- `dns_entropy.py` : Generates DNS queries with intentionally long, random subdomain labels to test the entropy/length based rule.

- `dns_timing.py` : Generates a high volume of DNS queries in a short period (or at fixed intervals) to test the rate based rule.

- `dns_randomisation.py` : Generates DNS queries with subdomains composed of base32 or hex strings to test the random pattern rule.

- `dns_all.py` : Generates mixed traffic that combines all the above patterns, to test the rules firing together.


## DNS Tunneling Detection Logic
The detection logic is implemented as Suricata IDS rules that inspect DNS traffic. These rules are deployed in Suricata’s `local.rules` and use Suricata’s DNS parsing and thresholding features. Below is a brief description of each rule, along with the actual rule signature and how it works.

### 1. High Entropy or Long DNS Subdomain Rule

This rule detects DNS queries containing a very long subdomain label (46 characters or more), which is a strong indicator of data encoding in DNS. Legitimate DNS queries almost never have such lengthy single labels. The rule uses a regular expression to find alphanumeric subdomains of length ≥46 in the DNS query name:

`alert dns any any -> any any (msg:"DNS TUNNEL: Long subdomain (>=46 chars)"; \
 dns.query; content:!"."; pcre:"/[A-Za-z0-9]{46,}\./"; classtype:trojan-activity; sid:2000001; rev:3;)`

- Purpose: Flags queries where the first subdomain, before the first dot, is extremely long and random looking. Attack tools like Iodine and DNScat2 use subdomain encoding, resulting in very long strings of seemingly random characters.

- Rationale: A subdomain label with ≥46 alphanumeric characters likely contains encoded binary data (e.g., base32 or base64 chunks) rather than a human readable name. 

- Threshold: The 46-character cutoff was chosen based on literature and dataset analysis indicating that genuine domain names stay below this length.

- Behaviour: When a DNS query like `ae29df7sgxh5g...7d.example.com` is observed, Suricata will trigger this alert. The message `DNS TUNNEL: Long subdomain (>=46 chars)” and classification “trojan-activity` will appear in logs. This rule focuses purely on the length/entropy aspect, regardless of query rate or content specifics.

### 2. High DNS Query Rate/Frequency Rule
This rule detects an abnormally high rate of DNS queries coming from a single host, which can indicate tunneling via many small queries. It leverages Suricata’s `detection_filter` threshold to track DNS query counts per source IP. Specifically, it alerts if a host makes 600 or more DNS requests within 60 seconds:

`alert dns any any -> any any (msg:"DNS TUNNEL: High DNS query rate (>600/min)"; \
 flow:to_server; detection_filter:track by_src, count 600, seconds 60; classtype:bad-unknown; sid:2000003; rev:2;)`

- Purpose: Identifies burst or persistently high DNS query volumes characteristic of DNS tunnels. Many tunneling implementations send thousands of queries per minute to push data since each DNS query carries limited bytes of payload.

- Rationale: Regular users and applications do not perform 600+ DNS lookups per minute from one machine. Such a rate 10 queries per second sustained is a red flag for automated data exfiltration or botnet activity. This rule is essentially a behavioural anomaly detector focusing on volume over content.

- Threshold: 600 queries/60s per source IP. This value was calibrated using benign traffic baselines to minimize false positives. It can be adjusted if needed for smaller or larger networks. The rule tracks each internal host Suricata `$HOME_NET` and will reset the count every 60 seconds.

- Behaviour: If an infected host is tunneling data (e.g., a malware sending 1000 DNS queries in one minute), Suricata will generate an alert “DNS TUNNEL: High DNS query rate (>600/min)”. This rule does not examine the content of queries, only the frequency, so it complements content based rules by catching tunnels that might use innocuous looking query names but at malicious speeds. In testing, this rule successfully caught high volume DNS bursts (e.g., a script sending queries in a tight loop) and remained quiet during normal DNS usage.

### 3. Randomised Subdomain Pattern Rule
This rule detects DNS queries whose subdomain appears to be algorithmically generated or encoded data in either hexadecimal or base32 format. It uses a single regex to catch two patterns: a hex string of length ≥30 or a base32 string (capital A-Z and digits 2-7) of length ≥20, at a label boundary. For example, it would match `3F9A7C0B21E4...` (hex) or `JBSWY3DPEHPK...` (base32) in the first subdomain. The Suricata rule is:

`alert dns any any -> any any (msg:"DNS TUNNEL: Hex/Base32-like subdomain"; \
 dns.query; pcre:"/\b([0-9A-Fa-f]{30,}|[A-Z2-7]{20,})\b/"; classtype:trojan-activity; sid:2000002; rev:2;)`

- Purpose: Flags queries where the subdomain consists of a long string of hex characters or base32 characters, which are common in DNS tunneling payload encoding. This catches not only extremely long labels, but also moderately long ones that have suspicious character composition (e.g., 20+ characters all in the set A-Z2-7).

- Rationale: Legitimate domain names typically include a mix of dictionary words, pronounceable syllables, or at least varied charsets (and rarely so many numeric or hex characters in a row). In contrast, covert channels may produce subdomains like `ABHXEZTQ39UGF...` or `4d3c2b1a...` that are essentially base32 or hex data chunks. By detecting these patterns, the rule can identify tunneling even if the overall length is not extreme.

- Detection Pattern: The PCRE regex uses word boundaries `(\b)` to ensure we match a whole label and not part of a longer string. It will trigger on:

     - Any contiguous hex string ≥30 chars (0-9, A-F).

     - Any contiguous “base32” string ≥20 chars (A-Z and 2-7, which covers base32 alphabet).

- Behaviour: When Suricata sees a DNS query like `dnsreq.A3F5B7C9E1D0.malicious.com` or `data.JBSWY3DPEHPKB.attacker.net`, it will trigger this rule. The alert `DNS TUNNEL: Hex/Base32-like subdomain` will be logged. It doesn’t matter what domain is being queried, it focuses purely on the subdomain format. This is advantageous because it can catch tunnels to arbitrary domains, even previously unknown ones. In testing, this rule caught various tunneling PCAPs that used encoded subdomains, including different record types, without needing any prior domain blacklist.

### Combined Ruleset
In practice, all three rules can be run simultaneously to maximise detection coverage. You can load each rule individually or enable all of them in Suricata. When all are active, the system can detect multiple aspects of tunneling behavior at once. For convenience, a combined version is provided. Running all rules may generate multiple alerts for the same malicious stream (e.g., a single tunneling session might trigger both the entropy rule and the rate rule), but this multi-feature detection ensures that different tunneling techniques are caught in the ruleset.

## Setup and Installation
Follow these steps to set up the DNS tunneling detection in your environment:

#### 1. Install Suricata 
If not already installed, download and install Suricata (the rules were developed and tested on Suricata 6.0+ running on Kali Linux, but any recent version should work). Ensure you have the ability to run Suricata in IDS mode on your network traffic or against test pcap files.

#### 2. Enable DNS logging 
In Suricata’s `suricata.yaml`, verify that the DNS application layer parser is enabled (it is by default for UDP/TCP 53). For example, ensure `app-layer.protocols.dns:` is set to yes. This ensures DNS fields are parsed for the dns.query content modifier to work. Also, enable the EVE DNS logging if you want JSON logs of DNS transactions.

#### 3. Add Custom Rules 
Locate your Suricata rules directory `/etc/suricata/rules/`. Create or open the `local.rules` file. Copy the three custom rule definitions into `local.rules`.

`alert dns any any -> any any (msg:"DNS TUNNEL: Long subdomain (>=46 chars)"; ... sid:2000001; rev:3;)`

`alert dns any any -> any any (msg:"DNS TUNNEL: High DNS query rate (>600/min)"; ... sid:2000003; rev:2;)`

`alert dns any any -> any any (msg:"DNS TUNNEL: Hex/Base32-like subdomain"; ... sid:2000002; rev:2;)`


#### 4. Suricata Configuration 
In `suricata.yaml`, ensure that `local.rules` is included in the rule-files list.

`rule-files: `

`- local.rules` 

`- suricata.rules`  

#### 5. Start Suricata 

Live monitoring: Identify the network interface that will carry DNS traffic (e.g., eth0). Run Suricata in IDS mode:

`sudo suricata -c /etc/suricata/suricata.yaml -i eth0`

#### 6. Run Traffic Generation Scripts
With Suricata running and the rules loaded, execute the Python scripts corresponding to the rules you want to test. Examples are provided in the next section. The scripts will emit DNS queries; if everything is set up, Suricata should log alerts for those queries. Make sure to run the scripts from a host/IP that is within Suricata’s HOME_NET (so that the rules apply to its outgoing DNS traffic).

#### 7. Check Alerts: Monitor Suricata’s outputs

- fast.log: Suricata’s fast alert log will contain one line alerts for each rule trigger with timestamp, alert message and source/dest IP.

- eve.json:  Check the JSON logs for detailed information (DNS query names, rule IDs, etc.).

- You should see alerts such as `DNS TUNNEL: Long subdomain (>=46 chars)` and others when running the scripts. If not, verify that the traffic is passing through Suricata.

## Usage Examples for Traffic Generation
Below are example commands to generate synthetic DNS traffic for each detection rule. These assume you have Suricata running with the custom rules loaded. You can adjust parameters (domain names, counts, intervals) as needed:

#### Rule 1 test: Generate 30 DNS queries with a long random subdomain (50 characters) to trigger the high entropy rule
`python3 dns_entropy.py longlabel --length 50 --count 30`

#### Rule 2 test: Generate 1000 DNS queries in quick succession (interval 0.05s) with ~50-char subdomains to trigger the high rate rule
`python3 dns_timing.py rate --resolver 127.0.0.1 --suffix testdomain.com --count 1000 --interval 0.05 --label-len 50`

#### Rule 3 test: Generate 50 DNS queries with a 50-character hex string subdomain (to 8.8.8.8) to trigger the randomisation rule
`python3 dns_randomisation.py hex --resolver 8.8.8.8 --suffix example.com --length 50 --count 50 --interval 0.1`

#### Combined test: Generate traffic pattern that includes long labels, fast queries and random subdomains together
`python3 dns_all.py`

## Key Evaluation Results
The custom ruleset was evaluated against several datasets and compared to default Suricata DNS rules. Results showed a substantial improvement in detecting DNS tunnels:

#### Detection vs. Default Suricata
On known DNS tunneling traces, the default Suricata rules produced zero alerts (they missed all tunneling activity), whereas the custom rules caught a significant portion of the malicious queries. This highlights the enhanced coverage provided by the new rules. For example, in one 24 hour DNScat2 tunnel capture, default Suricata triggered 0 alerts, but the custom ruleset detected over half of the malicious queries.

#### Dataset 1 : DNScat2 Tunnels
This dataset contained DNS queries from a DNScat2 malware C2 session (subdomain-encoded payloads). The randomisation rule (Rule 3) was the most effective single rule, detecting about 45.5% of the malicious queries with a Recall of ~45% and F1-score ~62.5%. The other single rules (entropy and rate) had near zero detection on this set (DNScat2’s patterns didn’t always exceed the 46-char length or the 600/min rate individually). However, when all rules were combined, the recall rose slightly to 46.4% (F1 ~63.4%). This means the combined approach caught a few extra cases (e.g. some queries that were long but not caught by the pattern rule alone). Precision was 100% in these tests (no false positives on benign traffic).

#### Dataset 2 - DoH : Encrypted DNS
In a scenario with DNS over HTTPS traffic (malicious DoH tunnel attempts), none of the custom rules triggered any alert. This was expected, as the DNS queries were encrypted inside HTTPS. The Suricata rules cannot inspect them. This result emphasises that the current approach is limited to unencrypted DNS. Detecting DoH-based tunneling required either decrypting the traffic or using other side channel heuristics, which were outside the project’s scope.

#### Dataset 3: Multiple Tunneling Tools
This was a more diverse set with various DNS tunneling techniques. The custom ruleset performed much better here:

- Combined rules achieved 81.7% Recall and 90% F1-score, detecting the majority of tunnel traffic.

- The best single rule on this set was again the random-pattern rule (~38-40% recall, mid-50s F1). The entropy rule also caught a significant subset. The rate rule triggered in relatively few cases, indicating many tunnels kept query rates below the threshold.

 - The combination of entropy + randomisation detections was complementary, covering different tunnel implementations and leading to the high combined recall.

- Precision remained 100% as no alerts were observed on the benign portion of traffic.

#### Dataset 4: Performance and False Alarms 
During testing on a benign dataset (CIC-IDS2017 DNS traffic), the custom ruleset did not produce any false positive alerts. This indicates the chosen thresholds and patterns were effective at avoiding normal traffic. However, on malicious datasets, the rules did produce a high volume of alerts. In a real network, this means the rules would catch the bad activity at the cost of many alerts, which is desirable for detection but could overwhelm analysts if not handled through aggregation or correlation. The precision being 100% in tests suggests that when an alert fires, it was indeed a true positive (given our test data); nonetheless, real world traffic may introduce some benign cases that mimic these patterns, so tuning might be needed per environment.

#### Rule Effectiveness
Overall, the entropy based and random subdomain rules proved most valuable, each targeting a different subset of tunnels that the other might miss. The high rate rule had a lesser impact in our datasets. This underscores that no single detection method catches all DNS tunnels, therefore using multiple complementary rules is the way to significantly raise detection coverage. For instance, some tunnels in Dataset 3 did not match the specific base32/hex regex, leading Rule 3 to miss them, but those same sessions might have had long labels that Rule 1 caught.

#### Resource Impact
The custom rules are relatively simple. Suricata handled them with negligible performance cost. The pattern matching is efficient and the detection_filter is optimised in Suricata. Therefore, the solution achieves the goal of improved detection without heavy performance overhead or need for ML algorithms, keeping it feasible for real time use.

## Limitations and Considerations
While this project provides an effective mechanism for detecting many DNS tunnel attempts, it’s important to understand its scope and limitations:

#### No Coverage of Encrypted DNS (DoH/DoT)
These rules cannot detect DNS over HTTPS, DNS over TLS, or DNS over QUIC traffic. If malware uses encrypted DNS channels, the query content and frequency become invisible to Suricata’s DNS parser (it would just see HTTPS traffic). Our tests on DoH traffic confirmed a complete blind spot. None of the custom rules fired. Mitigating this would require either decrypting the traffic via an SSL/TLS proxy or using heuristic analysis of encrypted traffic patterns (packet sizes, timing), which is beyond the current implementation. In practice, this means DNS tunneling over HTTPS can evade this ruleset. Organisations should deploy DoH detection techniques (e.g. block unknown DoH endpoints or use TLS inspection for DNS) if this vector is a concern.

#### Alert Volume and SOC Workflow
When these rules fire on real tunnel traffic, they can produce lots of alerts. for example, each DNS query will trigger the entropy rule). In a long running tunnel, hundreds or thousands of alerts could be logged. This is good from a detection standpoint but could overwhelm analysts with repetitive alerts. In testing, we saw the combined rule generate alerts for essentially every malicious query. To manage this:

- Consider using Suricata’s suppression or thresholding features in production to limit duplicate alerts. For instance, trigger the long subdomain alert at most once per minute per host, after the first hit.

- Integrate with a SIEM: Aggregate multiple alerts into a single incident or use correlation (e.g., if the same source IP triggers 100 “Long subdomain” alerts, the SIEM can bundle that as one event to investigate).

- Suricata’s fast.log will show only signature name and count, but EVE JSON logs can be used to script detection of “if X alerts in Y time, escalate as one incident.” This kind of tuning will make the rules more SOC friendly.

#### Tested Data vs. Real World
Our evaluation was done on known malicious DNS traffic datasets and a controlled benign set. Actual enterprise networks might have different DNS characteristics. Uncommon but legitimate scenarios could trigger these rules unexpectedly. For example, some Content Delivery Networks generate complex DNS names that might appear random, or an internal DNS based service registry might have frequent queries. These are edge cases, but security engineers should be aware and adjust the deployment; whitelist certain domains, raise thresholds slightly to minimise noise. Despite these considerations, any alert from these rules should be treated with scrutiny, as the patterns are strongly tied to malicious techniques.

## Future Development and Improvements

There are several avenues to enhance this project and address the limitations.

#### Encrypted DNS Detection
As encrypted DNS (DoH, DoT, DoQ) usage rises, future work should focus on detecting tunneling in those channels. Possible approaches:

- Decryption/Proxy: Use an enterprise TLS proxy or DOH parser to decrypt DNS over HTTPS on the fly and feed the plaintext into Suricata for analysis. This raises complexity and privacy considerations but technically enables reusing these rules on decrypted streams.

- Traffic Analysis: Develop heuristics for encrypted DNS without decryption. For example, analyse packet sizes, timings and frequencies of DoH traffic. A statistical model could detect patterns like consistent payload size. If data is encoded, responses might have a repeating size pattern or high request rates over HTTPS. Side channel analysis or machine learning could help flag suspicious DoH flows that mimic DNS tunneling behavior.

- DNS over HTTPS Fingerprinting: Identify and possibly block unknown DoH endpoints. Many browsers use well known DoH resolvers; an enterprise could allow those but alert on DNS to unusual HTTPS endpoints. While not directly our Suricata rules’ job, integration with threat intel on DoH hosts might help.

#### Integration with SIEM: 
Turn this into a more holistic solution. Feed Suricata alerts into a SIEM (Elastic, Splunk, Microsoft Sentinel, etc.) and enrich them. For instance, when a DNS tunnel alert happens, automatically cross reference with endpoint logs to see if a known process was making those queries or if it was an unusual process. This context can reduce false positives.

#### Machine Learning and Advanced Detection
Although our approach avoids the complexity of Machine Learning, future research could explore a hybrid model.

- Use ML on historical DNS logs to identify features that distinguish tunnels, then translate those into improved rules or anomaly scores.

- For example, a classifier might find that certain n-grams or lengths combos are predictive; if lightweight enough, these could become additional Suricata rules or a companion process that flags queries in real time for inspection.

- Train a model to detect DoH tunnels via timing.

#### Community and Threat Intel Updates

- As new DNS tunneling kits and malware emerge, update the ruleset accordingly. For instance, if a new tool uses base64 (which includes lowercase and symbols). Update the pattern or add a new one. Staying engaged with threat intel reports (e.g., reading articles on DNS abuse tactics) will inform such updates. The MITRE ATT&CK framework sub-technique T1071.004 (DNS C2) is a good reference. Tules already cover the techniques mentioned (long subdomains, frequent queries), but we should keep aligning with evolving attacker TTPs.

## Acknowledgments

- Suricata & Emerging Threats: Thanks to the open-source Suricata project and its community, whose DNS parsing and rule engine made this work possible. The default rulesets (Emerging Threats) provided a baseline to improve upon.

- DNS Tunneling Tools: This project was inspired by techniques used in tools like Iodine, DNScat2, dns2tcp, and others. Credit to their authors for highlighting what patterns to detect.

- Datasets Gratitude to:

     - Active Countermeasures: For the “Malware of the Day – DNScat2” pcap used as Dataset 1.

     - Canadian Institute for Cybersecurity: For the CIRA-CIC-DoHBrw-2020 dataset (Dataset 2) containing DoH traffic, which helped evaluate limitations in encrypted scenarios.

     - University of Twente: For the DNS Tunnel dataset (Dataset 3) that compiled various tunneling traces, enabling broader testing.

     - CIC-IDS2017: For a comprehensive benign traffic dataset (Dataset 4) to verify false positive rates.


<hr/>

##### SOC Analyst skills demonstrated 
<sub>This project demonstrates practical SOC capability across detection engineering and triage. I engineered Suricata IDS signatures using regex pattern matching and rate thresholding, then validated detections with controlled DNS traffic generation and dataset-based evaluation. The work shows I can translate attacker tradecraft into reliable alert logic, assess detection performance using recall, precision and F1 score and operationalise outputs using Suricata logs for investigation and escalation. It also shows clear understanding of DNS tunneling constraints, including encrypted DNS limitations and how to tune detections to balance coverage with analyst workload.</sub> 



