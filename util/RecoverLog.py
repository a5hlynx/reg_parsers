from Registry import Registry, RegistryLog
import os
from io import BytesIO
import sys

class RecoverLog:

    def __init__(self, hv):
        self.reg = None
        self._hv = BytesIO()
        with open(hv, "rb") as f:
            self._hv.write(f.read())
        self.log_1 = hv + ".LOG1"
        self.log_2 = hv + ".LOG2"
        self.__chk_logs()
        if self.__is_recovery_required():
            self.__recover_logs()
        else:
            self.reg = self.__registry_wrapper()

    def __chk_logs(self):
        if not os.path.isfile(self.log_1):
            self.log_1 = None
        if not os.path.isfile(self.log_2):
            self.log_2 = None

    def __is_recovery_required(self):
        _reg = self.__registry_wrapper()
        _r = _reg._regf.recovery_required()
        if not (_r.recover_header or _r.recover_data):
            return False
        return True

    def __registry_wrapper(self):
        try:
            self._hv.seek(0)
            _reg = Registry.Registry(self._hv)
        except Exception as e:
            print("%s." % e, file=sys.stderr)
            sys.exit(-1)
        return _reg

    def __registry_log_wrapper(self, log):
        try:
            self._hv.seek(0)
            _reg_log = RegistryLog.RegistryLog(self._hv, log)
        except Exception as e:
            print("%s." % e, file=sys.stderr)
            sys.exit(-1)
        return _reg_log

    def __recover_logs(self):
        _log_1 = None
        if self.log_1 is not None:
            _log_1 = self.__registry_log_wrapper(self.log_1)

        _log_2 = None
        if self.log_2 is not None:
            _log_2 = self.__registry_log_wrapper(self.log_2)

        _apply_1 = False
        _apply_2 = False
        _log_cnt = 0

        if (_log_1 is not None) and (_log_1.is_eligible_log()):
            _log_cnt +=1
            _apply_1 = True
        if (_log_2 is not None) and (_log_2.is_eligible_log()):
            _log_cnt +=1
            _apply_2 = True

        _reg = self.__registry_wrapper()
        _r = _reg._regf.recovery_required()
        if _log_cnt == 1:
            if _apply_1:
                _seq_num = _log_1.recover_hive()
            elif _apply_2:
                _seq_num = _log_2.recover_hive()
        elif _log_cnt == 2:
            _1_then_2 = _log_1.is_starting_log(_log_2)
            if (not _r.recover_header) and _1_then_2:
                _seq_num = _log_1.recover_hive()
                _seq_num = _log_2.recover_hive_continue(_seq_num + 1)
            elif (not _r.recover_header):
                _seq_num = _log_2.recover_hive()
                _seq_num = _log_1.recover_hive_continue(_seq_num + 1)
            else:
                if _1_then_2:
                    _seq_num = _log_2.recover_hive()
                else:
                    _seq_num = _log_1.recover_hive()

        self.reg = self.__registry_wrapper()

    def get_registry(self):
        return self.reg

