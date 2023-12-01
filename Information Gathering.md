# Information Gathering

## Passive Information Gathering

- **🌐 Website Recon & Footprinting**
  - `robots.txt`
  - `sitemap.xml`
  - Use add-ons like *BuiltWith* & *Wappalyzer*
  - Whois enumeration: `whois target.com`
  - Netcraft: [netcraft.com](https://www.netcraft.com/)

- **🔍 DNS Recon**
  - `dnsrecon -d target.com`
  - [dnsdumpster.com](https://dnsdumpster.com/)

- **🛡️ WAF Detection**
  - *wafw00f* tool (preinstalled in Kali)
  - Usage: `wafw00f target.com`

- **🔍 Subdomain Enumeration**
  - *sublist3r*
  - *Amass*
  - *subfinder*
  - *crt.sh*
  - You can check the usage of these tools ONLINE.

- **🔍 Google Dorking**
  - `site:target.com`
  - `site:target.com inurl:admin`
  - `site:*.target.com`
  - `site:*.target.com intitle:admin`
  - `site:dorkgpt.com intitle:DorkGPT`
  - For more Google dorking techniques, check [this website] [DorkGPT](https://dorkgpt.com/).

- **📧 Email Harvesting**
  - Tool: *theHarvester*
  - Usage: `theHarvester -d target.com -b google, linkedin`

- **🔒 Leaked Password Database**
  - [haveibeenpwned.com](https://haveibeenpwned.com/)

## Active Information Gathering

- **🔍 DNS Zone Transfer**
  - Tools: *dnsenum* & *dig*
  - Usage: `dnsenum zonetransfer.me`

- **🌐 Host Discovery with Nmap**
  - Usage: `sudo nmap -sn <target IP>/24`

- **🔍 Port Scanning with Nmap**
  - `nmap -p <port numbers you want to scan> <target IP>`

<div align="right"><font color="#3477b5">*Writer: Wael Rdifi*</font></div>

---