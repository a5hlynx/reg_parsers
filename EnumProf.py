import sys
if sys.version_info.major == 2:
    print("use python3.")
    sys.exit(0)

import os
from Registry import Registry
from struct import unpack
from argparse import ArgumentParser

class Prof:
    def __init__(self, sid):
        self.SID = sid
        self.ProfileImagePath = None
        self.Distinguished_Name = None
        self.User_Name = None
        self.Full_Name = None

    def set_image_path(self, image_path):
        self.ProfileImagePath = image_path

    def set_distinguished_name(self, distinguished_name):
        self.Distinguished_Name = distinguished_name

    def show(self):
        print("{:20s}".format("SID"), "{:<20s}".format(self.SID))
        if self.ProfileImagePath is None or len(self.ProfileImagePath) == 0:
            print("{:20s}".format("ProfileImagePath"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("ProfileImagePath"), "{:<20s}".format(self.ProfileImagePath))
        if self.Distinguished_Name is None or len(self.Distinguished_Name) == 0:
            print("{:20s}".format("Distinguished-Name"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("Distinguished-Name"), "{:<20s}".format(self.Distinguished_Name))
        if self.User_Name is None or len(self.User_Name) == 0:
            print("{:20s}".format("User Name"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("User Name"), "{:<20s}".format(self.User_Name))
        if self.Full_Name is None or len(self.Full_Name) == 0:
            print("{:20s}".format("Full Name"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("Full Name"), "{:<20s}".format(self.Full_Name))
        print("")
    def update_info(self, u):
        self.User_Name = u.get_user_name()
        self.Full_Name = u.get_full_name()

class Grp:
    def __init__(self, C):
        self.C = C
        self.Group_Name = None
        self.Comment = None
        self.Group_Members = []
        self.__parse_c()

    def __parse_c(self):
        _header = self.C[:0x34]
        _vals = unpack("<13L", _header)
        self.Group_Name = self.C[0x34+_vals[4]:0x34+_vals[4]+_vals[5]].decode()
        self.Comment = self.C[0x34+_vals[7]:0x34+_vals[7]+_vals[8]].decode()
        self.__parse_users()

    def __parse_users(self):
        _header = self.C[:0x34]
        _vals = unpack("<13L", _header)
        _num = _vals[12]
        _count = 0
        for __i in range(_num):
            _ofs = _vals[10] + 0x34 + _count
            _tmp, = unpack("<L", self.C[_ofs:_ofs+4])
            if _tmp == 0x101:
                if unpack("B", self.C[_ofs:_ofs+1]) == 0:
                    _ofs += 1
                self.__translate_sid(self.C[_ofs:_ofs+12])
                _count += 12
            elif _tmp == 0x501:
                self.__translate_sid(self.C[_ofs:_ofs+28])
                _count += 28

    def __translate_sid(self, sid):
        _sid = sid
        _len = len(_sid)
        if _len < 12:
            return
        if _len == 12:
            _revision, = unpack("B", _sid[:1])
            _idauth = _sid[2:8]
            _idauth = _idauth.hex().lstrip("0")
            _sub, = unpack("<L", _sid[8:12])
            self.Group_Members.append("S-" + str(_revision) + "-" + _idauth + "-" + str(_sub))
        elif _len > 12:
            _revision, = unpack("B", _sid[:1])
            _idauth = _sid[2:8]
            _idauth = _idauth.hex().lstrip("0")
            _sub = unpack("<4L", _sid[8:24])
            _rid, = unpack("<L", _sid[24:28])
            _s = "-".join(map(str, _sub))
            self.Group_Members.append("S-" + str(_revision) + "-" + _idauth + "-" + _s + "-" + str(_rid))

    def show(self):
        if len(self.Group_Members) > 0:
            print("{:20s}".format("Group Name"), "{:<20s}".format(self.Group_Name))
            _vn = True
            for _g in self.Group_Members:
                if _vn:
                    print("{:20s}".format("Group Members"), "{:<20s}".format(_g))
                    _vn = False
                else:
                    print("{:20s}".format(""), "{:<20s}".format(_g))

            print("")

class Usr():
    def __init__(self, local_sid, name, V):
        self.types = {}
        self.__set_types()
        self.V = V
        self.User_Name = None
        self.Full_Name = None
        self.Type = None
        self.Comment = None
        self.__parse_v()
        self.rid = str(int(name.lstrip("0"), 16))
        self.SID = local_sid + "-" + self.rid

    def __parse_v(self):
        _header = self.V[:44]
        _vals = unpack("<11L", _header)
        self.User_Name = self.V[_vals[3]+0xCC:_vals[3]+0xCC+_vals[4]].decode()
        self.Full_Name = self.V[_vals[6]+0xCC:_vals[6]+0xCC+_vals[7]].decode()
        self.Comment = self.V[_vals[9]+0xCC:_vals[9]+0xCC+_vals[10]].decode()
        if int(hex(_vals[1]),16) in self.types:
            self.Type = self.types[int(hex(_vals[1]),16)]

    def __set_types(self):
        self.types[0xbc] = "Default Admin User"
        self.types[0xd4] = "Custom Limited Acct"
        self.types[0xb0] = "Default Guest Acct"

    def get_sid(self):
        return self.SID

    def get_user_name(self):
        return self.User_Name

    def get_full_name(self):
        return self.Full_Name

    def get_comment(self):
        return self.Comment

class Acct():
    def __init__(self, V):
        self.V = V
        self.local_sid = ""
        self.Users = {}
        self.__parse_local_sid()

    def __parse_local_sid(self):
        _len = len(self.V)
        if _len > 12:
            _sub = unpack("<3L", self.V[_len-12:])
            if len(_sub) == 3:
                self.local_sid = "S-1-5-21-" + "-".join(map(str, _sub))

    def set_user(self, name, V):
        usr = Usr(self.local_sid, name, V)
        self.Users[usr.get_sid()] = usr

    def get_users(self):
        return self.Users

def main():
    parser = ArgumentParser()
    parser.add_argument("--sw", help="specify SoftWare Hive", required=True)
    parser.add_argument("--sam", help="specify SAM Hive", required=True)
    args = parser.parse_args()
    try:
        sw = Registry.Registry(args.sw)
        prof = sw.open("Microsoft\Windows NT\CurrentVersion\ProfileList")
        dn = sw.open("Microsoft\Windows\CurrentVersion\Group Policy\State")
    except Exception as e:
        print("%s." % e, file=sys.stderr)
        sys.exit(-1)

    Profs = {}
    for v in prof.subkeys():
        prof = Prof(v.name())
        for _v in v.values():
            if _v.name() == "ProfileImagePath":
                prof.set_image_path(_v.value())
        Profs[v.name()] = prof

    for v in dn.subkeys():
    	if v.name() in Profs:
            for _v in v.values():
                if _v.name() == "Distinguished-Name":
                     Profs[v.name()].set_distinguished_name(_v.value())

    try:
        sam = Registry.Registry(args.sam)
        account = sam.open("SAM\Domains\Account")
        alias = sam.open("SAM\Domains\Builtin\Aliases")
    except Exception as e:
        print("%s." % e, file=sys.stderr)
        sys.exit(-1)

    for v in account.values():
        if v.name() == "V":
            acct = Acct(v.value())
    for k in account.subkeys():
        if k.name() == "Users":
            for _k in k.subkeys():
                if len(_k.subkeys()) == 0:
                     for _v in _k.values():
                         if _v.name() == "V":
                            acct.set_user(_k.name(), _v.value())

    Grps = []
    for k in alias.subkeys():
        for _k in k.values():
            if _k.name() == "C":
                grp = Grp(_k.value())
                Grps.append(grp)

    for u in acct.get_users().values():
        if u.get_sid() not in Profs:
            prof = Prof(u.get_sid())
            Profs[u.get_sid()] = prof

        Profs[u.get_sid()].update_info(u)

    print("[Accounts]")
    for p in Profs.values():
        p.show()

    print("[Groups]")
    for g in Grps:
        g.show()



if __name__ == '__main__':
    main()
