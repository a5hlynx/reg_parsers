## Description

### PolAdtEv.py

Interprets and parses Audit Policy stored in `HKLM\Security\Policy\PolAdtEv`, which controls the output to Windows Security EventLog.

### EnumProf.py

Extracts the values of the following keys and enumerates them by SID
- ProfileImagePath from  `HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList` 
- Distinguished-Name from `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\State` 

## Requirements

The parsers run on Python3. Also requires [python-registry](https://github.com/williballenthin/python-registry). To satisfy the requirement, execute the following command, for instance.

```
$ pip3 install -r requirements.txt
```

## Usage

Currently, the parsers only interpret Registry Hive, which should be obtained beforehand.

```
$ python3 PolAdtEv.py -r <Security Hive>
$ python3 EnumProf.py -r <Software Hive>
```

## Examples


### PolAdtEv.py

Run the script with Security Hive specified, the result will be displayed to the stdout as shown below.

```
$ python3 PolAdtEv.py -r SECURITY
[System]
Security Stage Change                                 Success
Security System Extension                         No Auditing
System Integrity                          Success and Failure
IPsec Driver                                      No Auditing
Other System Events                       Success and Failure

..snip..

[Account Logon]
Credential Validation                             No Auditing
Kerberos Service Ticket Operations                No Auditing
Other Access Logon Events                         No Auditing
Kerberos Authentication Service                   No Auditing
```


### EnumProf.py

Run the script with Software Hive specified, the result will be displayed to the stdout as shown below.

```
$ python3 EnumProf.py -r SOFTWARE
SID                  S-1-5-18
ProfileImagePath     %systemroot%\system32\config\systemprofile
Distinguished-Name   -


SID                  S-1-5-19
ProfileImagePath     %systemroot%\ServiceProfiles\LocalService
Distinguished-Name   -

..snip..

SID                  S-1-5-21-4037123843-3514134998-4177948245-1105
ProfileImagePath     C:\Users\pparker
Distinguished-Name   CN=Peter Parker,CN=Users,DC=MARVEL,DC=local


SID                  S-1-5-21-4037123843-3514134998-4177948245-500
ProfileImagePath     C:\Users\Administrator
Distinguished-Name   CN=Administrator,CN=Users,DC=MARVEL,DC=local
```

## Documentation

- https://9ood4nothin9.blogspot.com/2021/12/parse-poladtev.html.
