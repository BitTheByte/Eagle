# Project Eagle (Alpha)
Project Eagle is a plugin based vulnerabilities scanner with threading support used for detection of low-hanging bugs on mass scale 
```
                              .---.        .-----------
                             /     \  __  /    ------
                            / /     \(  )/    -----
                           //////   ' \/ `   ---      Multipurpose vulnerability scanner
                          //// / // :    : ---                    v1.0b
                          / /   /  /`    '--                    2019-2020
                                    //..\\           
                               ====UU====UU====       
                                   '//||\\`           
                                     ''``
                                Project Eagle

```

<p align="center">
    Developed and maintained: <a href="https://twitter.com/BitTheByte">@BitTheByte</a>
    Idea: <a href="https://twitter.com/K4r1it0">@K4r1it0</a>
</p>

# Requirements
1) Python >= 3.6
2) Install python libraries 
```
$ python3 -m pip install -r requirements.txt
```
3) Works on Windows and Linux however windows is not the primary platform

# Usage 
#### Ping
This mode is only for checking online targets
```
$ python3 main.py -f domains.txt --ping
```
#### Basic usage
```
$ python3 main.py -f domains.txt
```
`domains.txt`: is a text file containing host names or ips, new line separated 
  
  
#### Advanced usage 
```
$ python3 main.py -f domains.txt -w 10 --db output.db.json
```
`domains.txt`: is a text file containing host names or ips, new line separated  
`output.db.json`: json formated output of the tool (will be used to restore state in future releases)  
`10`: is the number of working threads. keep in mind, workers are able to start workers for their work not limited by this number

#### Debug (verbose) mode
```
$ python3 main.py ...args -v*?
```
`v`: success, warning
`vv`:  success, warning, error
`vvv`: all suppored messages

# Features
1) CRLF
2) Senstive files e.g(`.git`, `info.php` ..)
3) Subdomain takeover 
4) Anonymous FTP login
5) S3 buckets misconfiguration including automatic takeover and upload
6) HTTP Request Sumggling
7) Firebase database misconfiguration
8) Senstive information disclosure e.g(`API Keys`, `Secrets` ..) including JS files and HTML pages
9) Missing SPF Records 
10) Path Traversal
11) PHP-CGI - CVE_2012_1823
12) Shell Shock - CVE_2014_6271
13) Struts RCE - CVE_2018_11776
14) WebLogic RCE - CVE_2019_2725
15) Confluence LFI - CVE_2019_3396
16) Ruby on Rails LFI - CVE_2019_5418
17) Atlassian SSRF - CVE_2019_8451
18) Apache Httpd mod_rewrite - CVE_2019_10098

# TODO-Features
- XSS Detection
- SSRF Attacks 
- Platform Delection 
- Platform Based attacks 
- Automatic Login bruteforce
- Automatic directory bruteforce
- Parameter gathering and fuzzing
- Detecting Error messages
- Ability to select plugins 
- Automatic updates
- Port Scanning and service detection
