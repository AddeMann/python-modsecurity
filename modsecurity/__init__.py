from typing import overload

import os, sys

if sys.platform == 'win32':
    __dll__ = 'libModSecurity.dll'
elif sys.platform == 'linux':
    __dll__ = 'libmodsecurity.so'

# Choose Windows display driver
if os.name == "nt":
    def _add_dll_directory():
        
        if os.path.exists('bin'):
            executable_dir = os.path.join(os.path.split(__file__)[0], 'bin')
            os.environ["PATH"] = os.environ["PATH"] + ";" + executable_dir
        msc_dir = os.path.join(os.path.split(__file__)[0], 'lib')

        # pypy does not find the dlls, so we add package folder to PATH.
        os.environ["PATH"] = os.environ["PATH"] + ";" + msc_dir

        # windows store python does not find the dlls, so we run this
        if sys.version_info > (3, 8):
            os.add_dll_directory(msc_dir)  # only available in 3.8+

        # cleanup namespace
        del msc_dir
        
    _add_dll_directory()
    
class MissingModule(Exception): ...
del MissingModule

try:
    import modsecurity.modsecurity as _msc
    from modsecurity.modsecurity import *
except ImportError:
    print("Could not import the ModSecurity C++ module 'modsecurity._modsecurity'.")
    raise

__version__ = _msc.__version__

class RulesSet(_msc.RulesSet):
    @property
    def amount_of_rules(self):
        return self._amount_of_rules
    def __init__(self):
        super().__init__()
        
        self._amount_of_rules = 0
    def load_from_uri(self, file):
        self._amount_of_rules += super().load_from_uri(file)
    def merge_rules(self, source) -> None:
        self._amount_of_rules += self.merge_rules(source)
    def dump_rules(self) -> None:
        self._amount_of_rules = 0
    def load_from_plaintext(self, plaintext):
        self._amount_of_rules += super().load_from_plaintext(plaintext)
    def load_from_remote(self, key, uri):
        self._amount_of_rules += super().load_from_remote(key, uri)
    def __repr__(self):
        return f'<modsecurity.{self.__class__.__name__} [{self.amount_of_rules} rules]>'
    
class ModSecurity(_msc.ModSecurity):
    _transaction_cls = Transaction
    @overload
    def new_transaction(rules_set: RulesSet, id: str) -> Transaction: ...
    @overload
    def new_transaction(rules_set: RulesSet) -> Transaction: ...
    def new_transaction(self, rules_set, id=None):
        if id is None:
            transaction = self._transaction_cls(self, rules_set)
        else:
            transaction = self._transaction_cls(self, rules_set, id)
        self._transactions.add(transaction)
        return transaction
    
    def __repr__(self) -> str:
        return f'<modsecurity.{self.__name__} "{self.who_am_i()}" [{len(self._transactions)} transactions]>'
    
def init():
    return ModSecurity()

ALL_LOG_PARTS = \
    _msc.AuditLogParts.AAuditLogPart | \
    _msc.AuditLogParts.BAuditLogPart | \
    _msc.AuditLogParts.CAuditLogPart | \
    _msc.AuditLogParts.DAuditLogPart | \
    _msc.AuditLogParts.EAuditLogPart | \
    _msc.AuditLogParts.FAuditLogPart | \
    _msc.AuditLogParts.GAuditLogPart | \
    _msc.AuditLogParts.HAuditLogPart | \
    _msc.AuditLogParts.IAuditLogPart | \
    _msc.AuditLogParts.JAuditLogPart | \
    _msc.AuditLogParts.KAuditLogPart | \
    _msc.AuditLogParts.ZAuditLogPart