# drupalcapwn

## Description
**drupalcapwn** is a - work in progress - Drupal Module Vulnerability Checker : It will check Drupal Security Advisories for vulnerabilities in a Drupal Module (as found with any drupal scanner like [droopescan](https://github.com/SamJoan/droopescan)) and can filter advisories having available exploits. 
* Uses Drupal API to build a local SQLite Database containing Drupal security advisories. 
* Display security advisories for a Drupal Module
* Display security advisories with known exploits
* Display recent security advisories (filter by year).
* Output security advisories in plain text or JSON.

## Installation 

Manual installation is as follows:

```
sudo apt install python3 python3-pip
git clone https://github.com/n3tsphere/drupalcapwn.git
cd drupalcapwn
python3 -m venv .
source bin/activate
pip install -r requirements.txt
python3 ./drupalcapwn.py --help
```

**IMPORTANT**: At first start-up *if no database file exists* : a **full database update** is launched and fetches every Drupal Advisories locally with Drupal API.
This full database update process takes time and must not be interrupted.
If database update is cancelled or interrupted, database will have an incomplete advisory list.  
A full update must be run next time with option `-fu` or `--full-update`. See chapter **`Database update interruption`**

## Usage 

```
$ ./drupalcapwn.py -h
usage: drupalcapwn.py [-h] [-m MODULE] [-i INPUT_FILE] [-e] [-y YEAR] [-j] [-o OUTPUT_FILE] [-nu] [-fu] [-db DATABASE] [-d] [-v]

DrupAlCapwn : Drupal Module Vulnerability Checker

optional arguments:
  -h, --help            show this help message and exit
  -m MODULE, --module MODULE
                        Drupal module name to look for, separated by commas (IE: -m drupal, -m webform,restws) (default: )
  -i INPUT_FILE, --input-file INPUT_FILE
                        File containing module names, one by line (default: )
  -e, --exploit-only    Display only vulnerabilities with available exploit (IE: not 'Theoretical' vulnerabilities) (default: False)
  -y YEAR, --year YEAR  Oldest year to start looking for advisories (default: )
  -j, --json            Output vulnerability results in JSON (default: False)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output vulnerability results in specific file (default: )
  -nu, --no-update      Disable automatic update check (default: False)
  -fu, --full-update    Force full update (default: False)
  -db DATABASE, --database DATABASE
                        Specify Database filename (default: advisories_drupal.db)
  -d, --debug           Display debug information (default: False)
  -v, --verbose         Verbose mode (default: False)

Examples:
  ./drupalcapwn.py -m drupal -e -j
  ./drupalcapwn.py -i input.txt -o output.txt -nu
```

### Example: Get security advisories for 'restws' module 
```
$ ./drupalcapwn.py -m restws
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Checking update for Drupal Security Advisories
[>] Database already up to date

[+] restws : 2 advisory found
   [>] restws (2019-02-20): 'RESTful Web Services - Critical - Access bypass - SA-CONTRIB-2019-018'
         Crit: AC:None/A:User/CI:All/II:All/E:Theoretical/TD:Default
         Type: Access bypass
         CVE : N/A
         URL : https://www.drupal.org/sa-contrib-2019-018
   [>] restws (2024-05-15): 'RESTful Web Services - Critical - Access bypass - SA-CONTRIB-2024-019'
         Crit: AC:None/A:None/CI:Some/II:None/E:Proof/TD:All
         Type: Access bypass
         CVE : N/A
         URL : https://www.drupal.org/sa-contrib-2024-019
```
### Example: Get security advisories for Drupal core since year 2024
```
$ ./drupalcapwn.py -m drupal -y 2024
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Checking update for Drupal Security Advisories
[>] Database already up to date

[+] drupal : 1 advisory found
   [>] drupal (2024-01-17): 'Drupal core - Moderately critical - Denial of Service - SA-CORE-2024-001'
         Crit: AC:None/A:None/CI:None/II:None/E:Theoretical/TD:Default
         Type: Denial of Service
         CVE : N/A
         URL : https://www.drupal.org/sa-core-2024-001
```
### Example: Get security advisories with available exploits for 'restws' and 'webform' modules
```
$ ./drupalcapwn.py -m restws,webform -e
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Checking update for Drupal Security Advisories
[>] Database already up to date

[+] restws : 1 advisory found
   [>] restws (2024-05-15): 'RESTful Web Services - Critical - Access bypass - SA-CONTRIB-2024-019'
         Crit: AC:None/A:None/CI:Some/II:None/E:Proof/TD:All
         Type: Access bypass
         CVE : N/A
         URL : https://www.drupal.org/sa-contrib-2024-019
[+] webform : 1 advisory found
   [>] webform (2021-03-03): 'Webform - Moderately critical - Access bypass - SA-CONTRIB-2021-004'
         Crit: AC:Basic/A:None/CI:None/II:None/E:Exploit/TD:Default
         Type: Access bypass
         CVE : N/A
         URL : https://www.drupal.org/sa-contrib-2021-004
```
### Example: Get security advisories for input file module list and output results in json to file

```
$ ./drupalcapwn.py -i input.txt -o output.json -j
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Checking update for Drupal Security Advisories
[>] Database already up to date

Output written to file 'output.json'
```


## Update Advisory Database

A local SQLite Database is build with advisories requested from Drupal API. 
* At first start-up if no database file exists : a **full database update** is launched and fetches every Drupal Advisories locally with Drupal API. 
* Each next run: update are checked and if needed an **incremental database update** is launched.

**IMPORTANT**: If database update is cancelled or interrupted, database will have an incomplete advisory list.
A full update must be run with option `-fu` or `--full-update`. See chapter **`Database update interruption`**

### Disable automatic update check
If database is up to date, automatic update check can be disabled with `-nu` option (Quick startup)
```
$ ./drupalcapwn.py -nu
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Skipping update check

No Drupal module provided : Use '-m' with module name or '-i' with input file. Use '-h' or '--help' for Help
```

### Force full update
**IMPORTANT**: If database update is cancelled or interrupted, database will have an incomplete advisory list. See chapter `Database update interruption`

```
$ ./drupalcapwn.py -fu
DrupAlCapwn v0.1 : Drupal Module Vulnerability Checker

[+] Performing full database update
[>] Updating Drupal Security Advisories Database (full update)

    !!! DO NOT PRESS [CTRL+C] OR INTERRUPT PROCESS !!!

    (F) Parsing Drupal Security Advisories : Page 1/11
    + 43318 (2006-01-04): securitydrupalorg - 'False Drupal XSS alarm on BugTraq - PSA-2006-001'
    + 184313 (2007-10-17): securitydrupalorg - 'PHP exploit using Drupal circulating - PSA-2007-001'
    + 372836 (2009-02-11): securitydrupalorg - 'Drupal core - Administer content types permission - PSA-2009-001'
    
    [...]

[>] Full update finished
```
### Database update interruption 
**IMPORTANT**: If `[Ctrl+C]` is pressed while update process is running or if update process is interrupted, the following message will be displayed : 
```
[!] Update aborted : DATABASE IS IN INCORRECT STATE, FULL UPDATE REQUIRED
[>] Next time perform full update with option '-fu' or '--full-update'
```
Database will have an incomplete advisory list, a full update must be run next time with option `-fu` or `--full-update` to get a complete list of all advisories.
