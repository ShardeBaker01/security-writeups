Boogeyman 1 — Phishing-to-Compromise Investigation

Platform: TryHackMe
Category: DFIR / Phishing Analysis / Endpoint & Network Forensics
Tools used: Thunderbird, LNKParse3, jq, Wireshark, tshark, CyberChef, KeePass/kpcli

Scenario

Julianne Westcott, a finance employee at Quick Logistics LLC, received a follow-up email about an unpaid invoice from a known business partner, B Packaging Inc. The attachment was malicious and compromised her workstation. I was asked to reconstruct the full attack chain from delivery through impact — approaching the artifacts cold before checking the room's guided questions, to keep the process as close to a real investigation as possible.

Objective

Identify the initial access vector, decode and analyze the delivered payload, trace endpoint execution, and determine what data — if any — was exfiltrated and how.

Investigation

Step 1 — Email Header Analysis

Opened the email in Thunderbird and inspected the raw source rather than the rendered message. The sending domain was a one-character typosquat of the real partner domain (bpakcaging.xyz vs. the legitimate bpackaging.xyz) — the kind of thing a busy finance employee would never catch at a glance. The DKIM-Signature and List-Unsubscribe headers pointed to ElasticEmail as the third-party relay used to send the message, a common tactic since abusing a reputable bulk-mail provider helps dodge domain-reputation-based spam filtering.

Step 2 — Attachment Extraction

The email body contained the password for a protected zip attachment (Invoice.zip). Password-protecting the payload is a deliberate move to defeat automated attachment scanners that can't open encrypted archives. Inside was a .lnk (Windows shortcut) file rather than a document with a macro — itself a signal this wasn't a typical "enable content" lure.

Step 3 — LNK / Endpoint Log Analysis

Ran the shortcut through LNKParse3 and found its "Command Line Arguments" field held a Base64-encoded PowerShell command rather than a plain executable path — a classic LOLBin evasion technique, since the process launched (powershell.exe) is fully legitimate and signed.

Decoding it took a second pass: my first CyberChef recipe order mangled the encoding, because PowerShell encodes its -EncodedCommand payloads as UTF-16LE, not standard UTF-8. Adding a "Decode text" step before the Base64 decode fixed it and revealed a command using .NET WebClient to download a second file from files.bpakcaging.xyz — confirming the attacker-controlled domain was doing double duty for both the phishing lure and payload hosting.

From there I pulled the PowerShell operational log (already converted from .evtx to JSON) and used jq to extract every ScriptBlockText value. This surfaced the full attacker toolkit dropped on the host: an enumeration binary (identified as Seatbelt, a legitimate open-source security-assessment tool being repurposed maliciously here) and a SQLite command-line tool (sq3.exe) used to query a local SQLite database directly — later identified as plum.sqlite, the data store behind Microsoft Sticky Notes.

Step 4 — Network Traffic Analysis

Pivoted to the packet capture in Wireshark, filtering on HTTP traffic to the known-bad domain/IP (167.71.211.113, cdn.bpakcaging.xyz:8080). Found repeated POST requests carrying decimal-encoded data — decoding that traffic in CyberChef confirmed the attacker was exfiltrating enumeration output and credential material over plain HTTP first.

The more interesting exfiltration channel showed up separately: filtering for DNS queries to the same malicious IP revealed hundreds of oddly-formed subdomain queries against bpakcaging.xyz. Rather than a normal C2 beacon, this was nslookup being used as a DNS exfiltration tool — each query's subdomain label was actually a hex-encoded chunk of a file, reassembled query-by-query. Stitching the query names together with tshark and decoding the hex in CyberChef reconstructed a .kdbx file — a KeePass password database pulled straight off the victim's machine.

Step 5 — Root Cause / Findings (plain-language summary)

A finance employee received what looked like a routine invoice email from a trusted partner. The email actually came from a lookalike domain and was sent through a legitimate bulk-mail service to slip past spam filters. The password-protected attachment defeated automated scanning, and inside was a shortcut file — not a document — that quietly launched PowerShell to download and run additional attacker tools. Those tools enumerated the machine, pulled data out of a local SQLite-based credential store, and used DNS lookups — a channel most firewalls don't inspect closely — to smuggle a KeePass password database off the machine. That database held stored financial credentials, meaning the attacker walked away with the ability to access sensitive company financial accounts, not just a single compromised workstation.

Key Indicators of Compromise (IOCs) Identified


Phishing/typosquat domain: bpakcaging.xyz (impersonating bpackaging.xyz)
Payload/C2 hosting domain: cdn.bpakcaging.xyz (port 8080)
Malicious destination IP: 167.71.211.113
Secondary C2 IP (PowerShell web requests): 159.89.205.40
Third-party mail relay abused for delivery: ElasticEmail
Delivery mechanism: password-protected .zip containing a malicious .lnk file
Execution technique: obfuscated/Base64-encoded PowerShell (UTF-16LE) launched via powershell.exe
Data staging tool: sq3.exe (SQLite CLI) used against a local credential database (plum.sqlite)
Exfiltration channel: DNS queries (hex-encoded subdomains) via nslookup
Data exfiltrated: KeePass database (.kdbx) containing stored financial credentials


What I'd Flag in a Real SOC Environment


Isolate immediately — confirmed execution plus confirmed exfil means this host gets pulled off the network now, not after root-cause is fully written up.
This wasn't opportunistic — I'd check mail logs across the whole finance department for anyone else who received or opened the same attachment.
DNS is a blind spot here — hundreds of DNS queries to one external domain went unnoticed; I'd push for DNS query logging and anomaly alerting (unusual query volume/entropy to a single domain) as a direct follow-up control.
Treat every credential in that vault as burned — force rotation immediately, including anything shared or service-account related that might have lived in the same KeePass file.
Share the typosquat domain with the impersonated partner — they may be getting spoofed against other customers too, and it's useful threat intel for them.
