## PolAdtEv.py

Interprets and parses Audit Policy stored in `HKLM\Security\Policy\PolAdtEv`, which controls the output to Windows Security EventLog.

## Requirements

PolAdtEv.py runs on Python3. Also requires [python-registry](https://github.com/williballenthin/python-registry). To satisfy the requirement, execute the following command, for instance.

```
$ pip3 install -r requirements.txt
```

## Usage

Currently, it only interprets Registry Hive, which should be obtained beforehand.

```
$ python3 PolAdtEv.py -r <Security Hive>
```

## Example

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

## Documentation

PolAdtEv.py is described at https://9ood4nothin9.blogspot.com/2021/12/parse-poladtev.html.