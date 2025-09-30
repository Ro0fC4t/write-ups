TimeLapse-WriteUp

# We started by scanning all TCP ports to identify exposed services.
# We used the following `nmap` command to detect all open TCP ports on the target. The `-Pn` flag skips host discovery (useful if ICMP is blocked), `-p-` scans all 65535 ports, and `-sS` performs a stealthy SYN scan.

```bash
sudo nmap --open -Pn -p- -sS -n -vvv 10.10.11.152

Starting Nmap 7.97 ( https://nmap.org ) at 2025-09-30 14:43 -0300

<SNIP>

Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5986/tcp  open  wsmans           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49719/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 501.03 seconds
           Raw packets sent: 196896 (8.663MB) | Rcvd: 345 (15.180KB)
```
