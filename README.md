# OIBSIP
Internship of Cyber Security Oasis Infobytes.

TASK-01--------------------------------------------------------------------------------------------------------------------------

Here's a detailed description report of an **Nmap port and service scan** of **Metasploitable2**, including an explanation of each **vulnerable service** discovered:

---

# **Nmap Port and Service Scan Report on Metasploitable2**

### **Target**: Metasploitable2

### **Scan Type**: Nmap TCP Port and Service Scan

### **Command Used**:

```bash
nmap -sS -sV -O -Pn <Target-IP>
```

---

## **Scan Summary**

| Attribute             | Details        |
| --------------------- | -------------- |
| **Scan Date**         | \[Insert Date] |
| **Scan Tool**         | Nmap           |
| **OS Detection**      | Enabled        |
| **Version Detection** | Enabled        |
| **Ping**              | Disabled (-Pn) |

---

## **Open Ports and Services Identified**

| Port | Protocol | Service      | Version                   | Vulnerability Summary                                     |
| ---- | -------- | ------------ | ------------------------- | --------------------------------------------------------- |
| 21   | TCP      | FTP          | vsftpd 2.3.4              | Backdoor vulnerability (CVE-2011-2523)                    |
| 22   | TCP      | SSH          | OpenSSH 4.7p1 Debian 8    | Weak keys, brute-force susceptible                        |
| 23   | TCP      | Telnet       | Linux telnetd             | Unencrypted login, no authentication hardening            |
| 25   | TCP      | SMTP         | Postfix smtpd             | Open relay, banner info leak                              |
| 53   | TCP/UDP  | DNS          | ISC BIND 9.4.2            | DNS cache poisoning, zone transfer                        |
| 80   | TCP      | HTTP         | Apache 2.2.8              | Multiple web app vulnerabilities (DVWA, Mutillidae, etc.) |
| 139  | TCP      | NetBIOS-SSN  | Samba smbd 3.X            | MS08-067, anonymous share enumeration                     |
| 445  | TCP      | Microsoft-DS | Samba smbd 3.X            | Remote code execution (RCE), SMBv1 vulnerabilities        |
| 512  | TCP      | exec         | BSD rexecd                | No authentication, command execution                      |
| 513  | TCP      | login        | BSD rlogin                | Unencrypted login                                         |
| 514  | TCP      | shell        | BSD rshd                  | Remote shell without proper authentication                |
| 1099 | TCP      | Java RMI     | Java RMI Registry         | Remote code execution (CVE-2011-3556)                     |
| 1524 | TCP      | shell        | Netcat backdoor           | Open reverse shell (no authentication)                    |
| 2049 | TCP/UDP  | NFS          | NFS (Network File System) | Anonymous access to exported shares                       |
| 2121 | TCP      | FTP          | ProFTPD                   | Vulnerable to command injection                           |
| 3306 | TCP      | MySQL        | MySQL 5.0.51a-3ubuntu5    | Weak/default credentials                                  |
| 3632 | TCP      | distcc       | distcc daemon             | Remote command execution (CVE-2004-2687)                  |
| 5432 | TCP      | PostgreSQL   | PostgreSQL 8.3.0          | Default credentials, remote access                        |
| 5900 | TCP      | VNC          | VNC protocol v1.3         | No authentication, screen hijack                          |
| 6000 | TCP      | X11          | X Windows                 | Remote GUI session hijack                                 |
| 8009 | TCP      | AJP13        | Apache JServ Protocol     | File inclusion & LFI (Ghostcat - CVE-2020-1938)           |
| 8180 | TCP      | HTTP         | Apache Tomcat 6           | Default creds, admin interface                            |

---

## **Detailed Vulnerable Service Analysis**

### 1. **FTP - vsftpd 2.3.4 (Port 21)**

* **Vulnerability**: Backdoor Command Execution (CVE-2011-2523)
* **Impact**: Allows remote attacker to spawn a shell by sending a crafted smiley `:)` in the username field.
* **Exploit Tool**: Metasploit module: `exploit/unix/ftp/vsftpd_234_backdoor`

---

### 2. **SSH - OpenSSH 4.7p1 (Port 22)**

* **Vulnerability**: Weak configuration and outdated version.
* **Risk**: Brute-force attacks due to lack of rate limiting; potential key reuse.
* **Fix**: Upgrade OpenSSH and enforce strong keys with rate limiting.

---

### 3. **Telnet (Port 23)**

* **Vulnerability**: Plaintext credentials, no encryption.
* **Risk**: Usernames and passwords can be sniffed.
* **Fix**: Disable Telnet; use SSH instead.

---

### 4. **SMTP - Postfix (Port 25)**

* **Vulnerability**: Potential open relay; banner leakage.
* **Risk**: May allow spam relay or mail spoofing.
* **Fix**: Disable relaying, enforce authentication.

---

### 5. **DNS - BIND 9.4.2 (Port 53)**

* **Vulnerability**: DNS cache poisoning, unauthorized zone transfer.
* **Fix**: Upgrade BIND, disable zone transfers.

---

### 6. **HTTP - Apache 2.2.8 (Port 80)**

* **Vulnerabilities**: Hosts multiple vulnerable web applications:

  * **DVWA**: SQLi, XSS, CSRF
  * **Mutillidae**: OWASP Top 10 vulnerabilities
  * **phpMyAdmin**: Default credentials, RCE
* **Fix**: Remove or patch vulnerable web apps.

---

### 7. **SMB - Samba 3.x (Ports 139, 445)**

* **Vulnerability**: MS08-067 (RCE), anonymous share access, weak SMB protocol (SMBv1).
* **Exploit Tool**: `msfconsole` with `exploit/windows/smb/ms08_067_netapi`
* **Fix**: Disable SMBv1, update Samba.

---

### 8. **R Services (Ports 512, 513, 514)**

* **Vulnerabilities**:

  * No authentication
  * Cleartext communication
* **Impact**: Remote command execution, credential theft.
* **Fix**: Disable these legacy services.

---

### 9. **Java RMI (Port 1099)**

* **Vulnerability**: Deserialization RCE (CVE-2011-3556)
* **Fix**: Disable RMI or use hardened security policies.

---

### 10. **Netcat Backdoor (Port 1524)**

* **Vulnerability**: Preconfigured reverse shell.
* **Impact**: Immediate root shell access without authentication.
* **Fix**: Remove or secure the Netcat listener.

---

### 11. **NFS - Network File System (Port 2049)**

* **Vulnerability**: Anonymous read/write to shared directories.
* **Fix**: Secure exports with proper permissions and authentication.

---

### 12. **ProFTPD (Port 2121)**

* **Vulnerability**: Command injection.
* **Exploit**: CVE-2006-5815 (mod\_copy); RCE using crafted input.
* **Fix**: Update ProFTPD or disable unused modules.

---

### 13. **MySQL (Port 3306)**

* **Vulnerability**: Default credentials (`root` with no password).
* **Risk**: Full database access.
* **Fix**: Change passwords, restrict access to localhost.

---

### 14. **distcc (Port 3632)**

* **Vulnerability**: RCE via improperly secured daemon (CVE-2004-2687).
* **Exploit**: Execute commands remotely.
* **Fix**: Restrict access or disable distcc.

---

### 15. **PostgreSQL (Port 5432)**

* **Vulnerability**: Default credentials.
* **Fix**: Update configuration, use strong passwords, restrict remote access.

---

### 16. **VNC (Port 5900)**

* **Vulnerability**: No authentication or weak passwords.
* **Impact**: Full desktop access.
* **Fix**: Enable authentication and restrict network access.

---

### 17. **X11 (Port 6000)**

* **Vulnerability**: Allows remote X sessions.
* **Impact**: GUI hijacking.
* **Fix**: Disable remote X11 access.

---

### 18. **Apache JServ Protocol - AJP13 (Port 8009)**

* **Vulnerability**: Ghostcat - LFI/RFI (CVE-2020-1938)
* **Fix**: Disable AJP or restrict access.

---

### 19. **Apache Tomcat (Port 8180)**

* **Vulnerability**: Default credentials, admin interface exposed.
* **Fix**: Change credentials, disable admin interface in production.

---

## **Conclusion**

Metasploitable2 contains a wide variety of **deliberately vulnerable services** to simulate real-world attack scenarios. These vulnerabilities are excellent for **penetration testing training** but must never be exposed to a public network.



Task-07-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Here's a detailed **Nikto vulnerability scan report** for **Metasploitable2**'s web services (typically on port 80 and 8180):

---

# **Nikto Web Server Vulnerability Scan Report**

### **Target**: Metasploitable2

### **Web Server Port**: 80 (Apache 2.2.8)

### **Scan Tool**: Nikto

### **Command Used**:

```bash
nikto -h http://<Target-IP>
```

---

## **Scan Summary**

| Attribute           | Details               |
| ------------------- | --------------------- |
| **Target Host**     | Metasploitable2       |
| **IP Address**      | \[Insert Target IP]   |
| **Web Server**      | Apache/2.2.8 (Ubuntu) |
| **Scan Start Time** | \[Insert Start Time]  |
| **Scan Duration**   | \[Insert Duration]    |
| **Nikto Version**   | \[e.g., Nikto 2.5.0]  |

---

## **High-Risk Findings**

### 1. **Apache Version Disclosure**

* **Issue**: Apache version 2.2.8 is outdated and vulnerable.
* **Details**: Server banner discloses: `Apache/2.2.8 (Ubuntu)`
* **Risk**: Multiple known vulnerabilities including DoS and RCE.
* **Recommendation**: Upgrade Apache to a currently supported version.

---

### 2. **X-Frame-Options Header Not Set**

* **Issue**: Site does not use `X-Frame-Options`.
* **Risk**: Vulnerable to Clickjacking attacks.
* **Fix**: Add `X-Frame-Options: DENY` or `SAMEORIGIN` header.

---

### 3. **X-XSS-Protection Header Not Set**

* **Issue**: No header to protect against reflected XSS.
* **Risk**: Allows browser-based script injection.
* **Fix**: Add `X-XSS-Protection: 1; mode=block` header.

---

### 4. **X-Content-Type-Options Not Set**

* **Issue**: Content-type sniffing is possible.
* **Risk**: May lead to MIME-sniffing attacks.
* **Fix**: Add `X-Content-Type-Options: nosniff` header.

---

### 5. **Directory Indexing Enabled**

* **Paths Found**:

  * `/icons/`
  * `/manual/`
  * `/phpmyadmin/`
* **Risk**: Exposes internal structure and potentially sensitive files.
* **Fix**: Disable directory listing via Apache config or `.htaccess`.

---

### 6. **phpMyAdmin Detected**

* **Path**: `/phpmyadmin/`
* **Risk**: Commonly attacked admin interface, possibly using default credentials.
* **Recommendation**: Secure access with authentication or IP whitelisting.

---

### 7. **Mutillidae Application Detected**

* **Path**: `/mutillidae/`
* **Risk**: Contains intentionally vulnerable code (SQLi, XSS, CSRF).
* **Fix**: Do not expose to public; use only in secure labs.

---

### 8. **DVWA Application Detected**

* **Path**: `/dvwa/`
* **Risk**: Contains known vulnerabilities used for security training.
* **Fix**: Isolate this application to internal use only.

---

### 9. **Outdated Apache Web Server**

* **Details**: Apache 2.2.8 has reached EOL (End-of-Life).
* **CVE Examples**:

  * CVE-2011-3192: Apache Range Header DoS
  * CVE-2009-3555: SSL Renegotiation Vulnerability
* **Fix**: Upgrade to latest stable release of Apache (e.g., 2.4.x+).

---

### 10. **robots.txt File Found**

* **Path**: `/robots.txt`
* **Info**: Can reveal sensitive or hidden directories.
* **Fix**: Ensure disallowed paths don’t contain sensitive content.

---

## **Other Observations**

| Finding                   | Status                                         |
| ------------------------- | ---------------------------------------------- |
| Server leaks version info | ✅                                              |
| Admin interfaces exposed  | ✅ (phpMyAdmin, DVWA, Mutillidae)               |
| SSL/TLS usage             | ❌ (no HTTPS found)                             |
| HTTP methods tested       | GET, POST, HEAD                                |
| CGI Scripts               | ✅ `/cgi-bin/` found (may include test scripts) |

---

## **Recommendations Summary**

1. **Patch and Upgrade**: Update Apache and all web applications to latest versions.
2. **Restrict Access**: Limit access to `/phpmyadmin`, `/dvwa`, and `/mutillidae`.
3. **Header Hardening**: Add security headers (X-Frame-Options, X-XSS-Protection, etc.).
4. **Disable Directory Listing**: Turn off indexes on all directories.
5. **Implement HTTPS**: Use SSL/TLS to encrypt web traffic.

---

## **Conclusion**

The Nikto scan reveals that Metasploitable2 is hosting multiple **intentionally insecure web applications** and running an **outdated Apache web server**, exposing it to numerous **critical web vulnerabilities**. These weaknesses serve educational purposes in a lab setup but represent significant risks if deployed in production or exposed externally.

Task-08--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Here's a sample **Wireshark analysis report** for a **basic HTTPS (SSL/TLS) traffic analysis**, intended for educational or internal security auditing purposes.

---

# **Wireshark HTTPS Traffic Analysis Report**

### **Tool**: Wireshark

### **Protocol**: HTTPS (SSL/TLS)

### **Analysis Type**: Basic Packet Capture and Protocol Inspection

### **Network Interface Used**: \[e.g., eth0 or Wi-Fi]

### **Capture Duration**: \[Insert duration]

### **File Captured**: \[e.g., https-capture.pcapng]

---

## **1. Objective**

To analyze HTTPS traffic using Wireshark to understand the structure of encrypted communications, identify SSL/TLS handshake stages, and verify certificate exchanges. This report does not involve decrypting HTTPS traffic but focuses on observing metadata and connection behavior.

---

## **2. Environment Details**

| Attribute                | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| Operating System         | \[e.g., Windows 10 / Kali Linux]                      |
| Wireshark Version        | \[e.g., 4.2.0]                                        |
| Browser/Application Used | \[e.g., Google Chrome to visit `https://example.com`] |
| Target Domain            | `https://example.com`                                 |
| Interface Filter Used    | `tcp.port == 443`                                     |

---

## **3. Filter and Setup**

* **Wireshark Display Filter**:

  ```
  ssl || tls || tcp.port == 443
  ```
* **Purpose**: To isolate and observe HTTPS (port 443) and TLS handshake traffic.

---

## **4. Key Findings**

### **a. TLS Handshake Observed**

* **Client Hello**:

  * Version: TLS 1.2 / TLS 1.3
  * Cipher Suites: Multiple (AES, CHACHA20, etc.)
  * Extensions: SNI (Server Name Indication), ALPN, etc.
  * Random value and session ID exchanged.

* **Server Hello**:

  * Version match with client.
  * Selected cipher suite returned.
  * Server certificate provided.
  * Encrypted extensions (in TLS 1.3).

---

### **b. Server Certificate Details**

* **Certificate Issuer**: e.g., Let's Encrypt / DigiCert
* **Common Name (CN)**: `example.com`
* **Validity Period**: Observed via certificate details tab.
* **Public Key Algorithm**: RSA / ECC

> 🔍 You can view the certificate in the "Server Hello" packet by expanding:

```
Transport Layer Security -> Handshake Protocol: Certificate
```

---

### **c. Encrypted Application Data**

* All payloads after the handshake are encrypted.
* These packets contain no readable content without a session key.
* Application Data records identified as:

  ```
  Content Type: Application Data (23)
  ```

---

### **d. Session Resumption (if observed)**

* TLS session resumption detected via:

  * Session ID reuse (TLS 1.2)
  * Pre-shared key exchange (TLS 1.3)
* Reduces handshake overhead in repeated connections.

---

## **5. Limitations**

* **No Decryption**: Without private keys or session secrets, payload content is unreadable.
* **Need for Decryption Key**: To decrypt, you need:

  * Server private key (not feasible for HTTPS)
  * SSLKEYLOGFILE (from browser for client-side logging)

---

## **6. Recommendations**

* **Use Decryption for Deep Analysis**: If analyzing known traffic (e.g., your own server or browser with SSLKEYLOGFILE), enable decryption in Wireshark for full visibility.
* **Monitor Certificates**: Ensure certificates are valid and from trusted authorities.
* **Check Cipher Strength**: Avoid weak ciphers like RC4, prefer strong options like AES-GCM or CHACHA20.
* **Watch for Anomalies**: Repeated failed handshakes, suspicious cipher negotiation, or malformed TLS records could indicate attacks or misconfigurations.

---

## **7. Conclusion**

The Wireshark analysis successfully captured and examined the structure of an HTTPS session. While the encrypted content remains opaque (as expected), the **TLS handshake**, **certificate exchange**, and **secure session setup** were clearly observed and validated. No anomalies or insecure configurations were found in this session.

Task-05-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

The report is present in this directory named Socali_Engi.......
