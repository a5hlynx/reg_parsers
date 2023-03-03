import sys
if sys.version_info.major == 2:
    print("use python3.")
    sys.exit(0)

import os
from Registry import Registry
from struct import unpack
from argparse import ArgumentParser
import inspect
import pprint

class Prof:
    def __init__(self, sid):
        self.SID = sid
        self.ProfileImagePath = None
        self.Distinguished_Name = None

    def set_image_path(self, image_path):
        self.ProfileImagePath = image_path

    def set_distinguished_name(self, distinguished_name):
        self.Distinguished_Name = distinguished_name

    def show(self):
        print("{:20s}".format("SID"), "{:<20s}".format(self.SID))
        if self.ProfileImagePath is None:
            print("{:20s}".format("ProfileImagePath"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("ProfileImagePath"), "{:<20s}".format(self.ProfileImagePath))
        if self.Distinguished_Name is None:
            print("{:20s}".format("Distinguished-Name"), "{:<20s}".format("-"))
        else:
            print("{:20s}".format("Distinguished-Name"), "{:<20s}".format(self.Distinguished_Name))
        print("\n")

def main():
    parser = ArgumentParser()
    parser.add_argument("-r", "--registry", help="specify SoftWare hive to enumerate Profile", required=True)
    args = parser.parse_args()
    try:
        reg = Registry.Registry(args.registry)
        prof = reg.open("Microsoft\Windows NT\CurrentVersion\ProfileList")
        dn = reg.open("Microsoft\Windows\CurrentVersion\Group Policy\State")
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

    for pf in Profs.values():
        pf.show()

if __name__ == '__main__':
    main()
