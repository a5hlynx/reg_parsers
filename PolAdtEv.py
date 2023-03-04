# registry structures are taken from https://www.kazamiya.net/files/projects/PolAdtEv_Structure_en_rev4.pdf

import sys
if sys.version_info.major == 2:
    print("use python3.")
    sys.exit(0)

import os
from Registry import Registry
from struct import unpack
from argparse import ArgumentParser

class PolAdtEv:
    def __init__(self, data):
        self.data = data
        self.len = len(data)
        self.categ_num, = unpack("<H", data[4:6])
        self.header_len = 0xc

        self.categories          =  ["System", "Logon/Logoff", "Object Access", \
                                     "Privilege Use", "Detailed Tracking", "Policy Change", \
                                     "Account Management", "DS Access", "Account Logon"]
        self.subcategory_num     =  [0 ,0 ,0, 0, 0, 0, 0, 0, 0]
        self.category_offset     =  [0, 0, 0, 0, 0, 0, 0, 0, 0]
        self.system              =  {"Security State Change":"", "Security System Extension":"", \
                                     "System Integrity":"", "IPsec Driver":"", \
                                     "Other System Events":""}
        self.logon_logoff        =  {"Logon":"", "Logoff":"", "Account Lockout":"", \
                                     "IPsec Main Mode":"", "Special Logon":"", \
                                     "IPsec Quick Mode":"", "IPsec Extended Mode":"", \
                                     "Other Logon/Logoff Events":"", "Network Policy Server":"", \
                                     "User/Device Claims":"", "Group Membership":""}
        self.object_access       =  {"File System":"", "Registry":"", "Kernel Object":"", \
                                     "SAM":"", "Other Object Access Events":"", "Certification Services":"", \
                                     "Application Generated":"", "Handle Manipulation":"", "File Share":"", \
                                     "Filtering Platform Packet Drop":"", "Filtering Platform Connection":"", \
                                     "Detailed File Share":"", "Removable Storage":"", "Central Access Policy Staging":""}
        self.privilege_use       =  {"Sensitive Privilege Use":"", "Non Sensitive Privilege Use":"", \
                                     "Other Privilege Use Events":""}
        self.detailed_tracking   =  {"Process Creation":"", "Process Termination":"", "DPAPI activity":"", \
                                     "RPC Events":"", "Plug and Play Events":"", "Token Right Adjusted Events":""}
        self.policy_change       =  {"Audit Policy Change":"", "Authentication Policy Change":"", \
                                     "Authorization Policy Change":"", "MPSSVC Rule-Level Policy Change":"", \
                                     "Filtering Platform Policy Change":"", "Other Policy Change Events":""}
        self.account_management  =  {"User Account Management":"", "Computer Account Management":"", \
                                     "Security Group Management":"", "Distribution Group Management":"", \
                                     "Application Group Management":"", "Other Account Management Events":""}
        self.ds_access           =  {"Directory Service Access":"", "Directory Service Change":"", \
                                     "Directory Service Replication":"", "Detailed Directory Service Replication":""}
        self.account_logon       =  {"Credential Validation":"", "Kerberos Service Ticket Operations":"", \
                                     "Other Access Logon Events":"", "Kerberos Authentication Service":""}

        self.category_dictionary =  [self.system, self.logon_logoff, self.object_access, \
                                     self.privilege_use, self.detailed_tracking, \
                                     self.policy_change, self.account_management, \
                                     self.ds_access, self.account_logon]
        self.__set_sub_category()

        self.__parse_audit()

    def __hex_to_string(self, _hex):
        _str = "Unknown" 
        if _hex == 0:
           _str = "No Auditing"
        elif _hex == 1:
           _str = "Success"
        elif _hex == 2:
           _str = "Failure"
        elif _hex == 3:
           _str = "Success and Failure"

        return _str

    def __parse_audit(self):
        for _i in range(self.categ_num):
            _o = self.category_offset[_i]
            _sc = self.category_dictionary[_i]
            _keys = list(_sc.keys())
            for __i in range(self.subcategory_num[_i]):
                _h, = unpack("<H", self.data[_o:_o+2])
                _sc[_keys[__i]] = self.__hex_to_string(_h)
                _o += 2

    def __set_sub_category(self):
        if len(self.subcategory_num) > self.categ_num:
            print("data might be corruptted.", file=sys.stderr)
            sys.exit(-1) 

        _sub_category_num_offset, = unpack("<H", self.data[8:10])
        _category_offset = self.header_len
        for _i in range(self.categ_num):
            self.subcategory_num[_i], = unpack("<H", self.data[_sub_category_num_offset:_sub_category_num_offset+2])
            self.category_offset[_i] = _category_offset
            _sub_category_num_offset += 2
            _category_offset += 2 * self.subcategory_num[_i]

    def show(self):
        for _i in range(self.categ_num):
            print("[%s]" % self.categories[_i] )
            for _k, _v in self.category_dictionary[_i].items():
                if len(_v) > 0:
                    print("{:40s}".format(_k), "{:>20s}".format(_v))
            print("")

def main():

    parser = ArgumentParser()
    parser.add_argument("--sec", help="specify the Security Hive", required=True)
    args = parser.parse_args()
    try:
        reg = Registry.Registry(args.registry)
        key = reg.open("Policy\\PolAdtEv")
    except Exception as e:
        print("%s." % e, file=sys.stderr)
        sys.exit(-1)

    data=None
    for value in[v for v in key.values()]:
        data=value.value()

    if data is None:
        print("any data cannot be retrieved.", file=sys.stderr)
        sys.exit(-1)
    
    pol = PolAdtEv(data)
    pol.show()

if __name__ == '__main__':
    main()
