## Description

### PolAdtEv.py

Parses PolAdtEV extracted from Security Hive and enumerates Audit Policy, which controls the output to Windows Security EventLog.

### EnumProf.py

Parses Accounts/Groups information extracted from Software/Sam Hives and enumerates them.


## Requirements

The parsers run on Python3. Also requires [python-registry](https://github.com/williballenthin/python-registry). To satisfy the requirement, execute the following command, for instance.

```
$ pip3 install -r requirements.txt
```

## Usage

Currently, the parsers only interpret Registry Hive, which should be obtained beforehand.

```
$ python3 PolAdtEv.py --sec <Security Hive>
$ python3 EnumProf.py --sw <Software Hive> --sam <Sam Hive>
```

## Examples


### PolAdtEv.py

Run the script with Security Hive specified, the result will be displayed to the stdout as shown below.

```
$ python3 PolAdtEv.py --sec SECURITY
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

Run the script with Software/Sam Hives specified, the result will be displayed to the stdout as shown below.

```
$ python3 EnumProf.py --sw SOFTWARE --sam SAM
[Accounts]
SID                  S-1-5-18
ProfileImagePath     %systemroot%\system32\config\systemprofile
Distinguished-Name   -
User Name            -
Full Name            -

..snip..

SID                  S-1-5-21-4037123843-3514134998-4177948245-1103
ProfileImagePath     C:\Users\fcastle
Distinguished-Name   CN=Frank Castle,CN=Users,DC=MARVEL,DC=local
User Name            -
Full Name            -

..snip..

[Groups]
Group Name           Administrators
Group Members        S-1-5-21-4005366961-3971355847-3980901421-500
                     S-1-5-21-4005366961-3971355847-3980901421-1001
                     S-1-5-21-4037123843-3514134998-4177948245-512
                     S-1-5-21-4037123843-3514134998-4177948245-1105
                     S-1-5-21-4037123843-3514134998-4177948245-1103

..snip..

Group Name           System Managed Accounts Group
Group Members        S-1-5-21-4005366961-3971355847-3980901421-503
```

## Documentation

- [PolAdtEv.py](https://9ood4nothin9.blogspot.com/2021/12/parse-poladtev.html).
- [EnumProf.py](https://9ood4nothin9.blogspot.com/2023/03/parse-accountsgroups-infomation.html).