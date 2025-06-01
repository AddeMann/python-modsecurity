# distutils: language = c++
# cython: binding=True

cimport libmodsecurity as lib
from typing import Callable, Any

from libcpp.string cimport string
from libcpp.list cimport list as _list
from libc.stdint cimport int32_t
from libcpp.typeinfo cimport type_info
from libcpp.iterator cimport iterator

from libcpp.memory cimport unique_ptr
from libcpp.string cimport string
from libcpp.vector cimport vector

from libc.stdlib cimport free, malloc

from cpython.object cimport PyObject
from cpython.tuple cimport PyTuple_Pack

from typing import overload

from enum import IntEnum
import json

cdef object _cinit_sentinel = object()

def _create_construction_error(name: str):
    return RuntimeError(f"Cannot construct modsecurity.{name}")

__version__ = lib.MODSECURITY_VERSION

# Enum types
class RequestBodyType(IntEnum):
    """
    Types of request body that ModSecurity may give a special treatment for the data.
    
    Attributes:
    -----------
    - ```UnknownFormat```: The request body format is unknown or unsupported.
    - ```MultiPartRequestBody```: The request body is in `multipart/form-data` format.
    - ```WWWFormUrlEncoded```: The request body is in `application/x-www-form-urlencoded` format.
    - ```JSONRequestBody```: The request body is in JSON format.
    - ```XMLRequestBody```: The request body is in XML format.
    """

    UnknownFormat = 0
    """The request body format is unknown or unsupported."""
    MultiPartRequestBody = 1
    """The request body is in `multipart/form-data` format."""
    WWWFormUrlEncoded = 2
    """The request body is in `application/x-www-form-urlencoded` format."""
    JSONRequestBody = 3
    """The request body is in JSON format."""
    XMLRequestBody = 4
    """The request body is in XML format."""

class Phases(IntEnum):
    """
    Represents the different processing phases in ModSecurity.
    
    Attributes:
    -----------
        - ```ConnectionPhase```: The phase when a connection is established.
        - ```UriPhase```: The phase where the request URI is processed.
        - ```RequestHeadersPhase```: The phase where request headers are analyzed.
        - ```RequestBodyPhase```: The phase where the request body is processed.
        - ```ResponseHeadersPhase```: The phase where response headers are analyzed.
        - ```ResponseBodyPhase```: The phase where the response body is processed.
        - ```LoggingPhase```: The phase where logs are generated for the request.
        - `NUMBER_OF_PHASES`: The total number of defined processing phases.
    """
    ConnectionPhase = lib.Phases.ConnectionPhase
    """The phase when a connection is established."""
    UriPhase = lib.Phases.UriPhase
    """The phase where the request URI is processed."""
    RequestHeadersPhase = lib.Phases.RequestHeadersPhase
    """The phase where request headers are analyzed."""
    RequestBodyPhase = lib.Phases.RequestBodyPhase
    """The phase where the request body is processed."""
    ResponseHeadersPhase = lib.Phases.ResponseHeadersPhase
    """The phase where response headers are analyzed."""
    ResponseBodyPhase = lib.Phases.ResponseBodyPhase
    """The phase where the response body is processed."""
    LoggingPhase = lib.Phases.LoggingPhase
    """The phase where logs are generated for the request."""
    NUMBER_OF_PHASES = lib.Phases.NUMBER_OF_PHASES
    """The total number of defined processing phases."""

class LogProperty(IntEnum):
    """
    Defines logging properties for ModSecurity.
    
    Attributes:
    -----------
        - ```TextLogProperty```: Enables standard text-based logging.
        - ```RuleMessageLogProperty```: Includes rule messages in the logs.
        - ```IncludeFullHighlightLogProperty```: Enables full highlighting of log messages.
    """
    TextLogProperty = 1
    """Enables standard text-based logging."""
    RuleMessageLogProperty = 2
    """Includes rule messages in the logs."""
    IncludeFullHighlightLogProperty = 4
    """Enables full highlighting of log messages."""

TextLogProperty = LogProperty.TextLogProperty
TextLogProperty.__doc__ = LogProperty.TextLogProperty.__doc__
RuleMessageLogProperty = LogProperty.RuleMessageLogProperty
RuleMessageLogProperty.__doc__ = LogProperty.RuleMessageLogProperty.__doc__
IncludeFullHighlightLogProperty = LogProperty.IncludeFullHighlightLogProperty
IncludeFullHighlightLogProperty.__doc__ = LogProperty.IncludeFullHighlightLogProperty.__doc__


# Error types
class ModSecurityError(Exception):
    strerror: str
    __module__ = 'modsecurity'

    def __init__(self, strerror: str) -> None:
        self.strerror = strerror
        message = f'ModSecurityError: {strerror}'
        super(ModSecurityError, self).__init__(message)

class RulesSetError(RuntimeError):
    """
    Error class for rules set errors
    """
    def __init__(self, code, log=None):
        self.code = code
        self.log = log
        message = f'RulesSetError: [ErrorCode:{code} - Parsing error]: {log}'
        super(RulesSetError, self).__init__(message)
        
class TransactionError(RuntimeError):
    """
    Error class for transaction errors
    """
    def __init__(self, log, id=None, remote_addr=None):
        self.log = log
        self.id = id
        self.remote_addr = remote_addr
        if id == None:
            super(TransactionError, self).__init__(f'TransactionError: [RemoteAddr: {remote_addr}] {log}')
        else:
            super(TransactionError, self).__init__(f'TransactionError: [TransactionId: {id}] {log}')

cpdef bool_error_check(int code, id, log=None):
    if bool(code) == False:
        raise TransactionError(code, id, log)
    else:
        return None

            
#               ---- File: modsecurity/intervention.h ----
cdef class Intervention:
    @property
    def status(self):
        return self._status
    @status.setter
    def status(self, value: int):
        self._status = value
    @property
    def pause(self):
        return self._pause
    @pause.setter
    def pause(self, value: int):
        self._pause = value
    @property
    def url(self):
        return self._url
    @url.setter
    def url(self, value: str):
        self._url = value
    @property
    def log(self):
        return self._log
    @log.setter
    def log(self, value: str):
        self._log = value
    @property
    def disruptive(self):
        return bool(self._disruptive)
    @disruptive.setter
    def disruptive(self, value: int):
        self._disruptive = value

    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise RuntimeError(f'Cannot construct msc.Intervention')

cdef void _msc_intervention_free(lib.ModSecurityIntervention *ptr):
    if ptr != NULL:
        lib.free(ptr)
        
cdef Intervention create_msc_intervention():
    cdef Intervention i = Intervention(_cinit_sentinel)
    return i

cpdef list[Intervention] create_intervention_instances(vector[lib.ModSecurityIntervention] data):
    cdef Intervention obj

    _intervention_instances = []
    if data.size() > 0:
        for _intervention in data:
            intervention = &_intervention
            obj = create_msc_intervention()
            try:
                obj.status = intervention.status
                obj.pause = intervention.pause
                obj.url = intervention.url if intervention.url != NULL else None
                obj.log = intervention.log if intervention.log != NULL else None
                obj.disruptive = bool(intervention.disruptive)
            finally:
                _intervention_instances.append(obj)
    return _intervention_instances

    
#               ---- File: modsecurity/variable_value.h ----
cdef class VariableValue:
    cdef lib.VariableValue* ptr
    def __cinit__(self, collection=None, key=None, value=None):
        cdef string _collection
        cdef string _key
        cdef string _value

        if value:
            _value = value.encode()
        if not collection and key:
            _key = key.encode()

            self.ptr = new lib.VariableValue(&_key, &_value if value != None else NULL)
        elif collection and key:
            _collection = collection.encode()
            _key = key.encode()
            self.ptr = new lib.VariableValue(&_collection, &_key, &_value if value != None else NULL)

    def get_key(self) -> str:
        return self.ptr.getKey().c_str()
    def get_key_with_collection(self) -> str:
        return self.ptr.getKeyWithCollection().c_str()
    def get_collection(self) -> str:
        return self.ptr.getCollection().c_str()
    def get_value(self) -> str:
        return self.ptr.getValue().c_str()

    def set_value(self, value: str) -> None:
        cdef string _value
        self.ptr.setValue(_value.assign(<const char*>value))
    def reserve_origin(self, additional_size: int) -> None:
        self.ptr.reserveOrigin(<size_t>additional_size)

        
#   =======================================================================
#     Header Name:  modsecurity/collection/collection.h
#     Classes:
#       - Collection() = Cannot be constructed.
#   =======================================================================

cdef Collection wrap_collection_class(lib.Collection *instance):
    cdef Collection obj = Collection(_cinit_sentinel)
    
    obj.set_ptr(instance)
    return obj

cdef class Collection:

    cdef lib.Collection *ptr
    @property
    def name(self):
        return self.ptr.m_name.c_str()
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)
        
    cdef void set_ptr(self, lib.Collection *ptr):
        self.ptr = ptr

    @overload
    def resolve(self, key: str) -> str | None: ...
    @overload
    def resolve(self, key: str, compartment: str) -> str | None: ...
    @overload
    def resolve(self, key: str, compartment: str, compartment2: str) -> str | None: ...
    def resolve(self, key: str, compartment=None, compartment2=None):
        cdef string key_string
        cdef string _compartment
        cdef string _compartment2

        if compartment == None and compartment2 == None:
            value = <unique_ptr[string]>self.ptr.resolveFirst(key_string.assign(<const char*>key))
        elif compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            value = <unique_ptr[string]>self.ptr.resolveFirst(key_string.assign(<const char*>key), _compartment)

        elif compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            value = <unique_ptr[string]>self.ptr.resolveFirst(key_string.assign(<const char*>key), _compartment, _compartment2)
        
        if value == NULL:
            _value = None
        else:
            _value = value.get().c_str()
        return _value

    @overload       
    def store(self, key: str, value: Any) -> None: ...
    @overload
    def store(self, key: str, compartment: str, value: Any) -> None: ...
    @overload
    def store(self, key: str, compartment: str, compartment2: str, value: Any) -> None: ...
    def store(self, key, compartment=None, compartment2=None, value=''):
        cdef string key_string
        cdef string _compartment
        cdef string _compartment2
        cdef string value_string
        cdef int error

        if compartment == None and compartment2 == None:
            error = <int>self.ptr.storeOrUpdateFirst(key_string.assign(<const char*>key), value_string.assign(<const char*>value))
            
            if bool(error) == False:
                raise KeyError(key)

        if compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            error = <int>self.ptr.storeOrUpdateFirst(key_string.assign(<const char*>key), _compartment, value_string.assign(<const char*>value))

            if bool(error) == False:
                raise KeyError(key)

        if compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            error = <int>self.ptr.storeOrUpdateFirst(key_string.assign(<const char*>key), _compartment, _compartment2, value_string.assign(<const char*>value))

            if bool(error) == False:
                raise KeyError(key)

    @overload
    def pop(self, key: str) -> None: ...
    @overload
    def pop(self, key: str, compartment: str) -> None: ...
    @overload
    def pop(self, key: str, compartment: str, compartment2: str) -> None: ...
    def pop(self, key, compartment=None, compartment2=None):
        cdef string key_string
        cdef string _compartment
        cdef string _compartment2

        if compartment == None and compartment2 == None:
            self.ptr._del(key_string.assign(<const char*>key))

        if compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            self.ptr._del(key_string.assign(<const char*>key), _compartment)
            
        if compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            self.ptr._del(key_string.assign(<const char*>key), _compartment, _compartment2)

        return None

    @overload
    def update(self, key: str, value: Any) -> None: ...
    @overload
    def update(self, key: str, compartment: str, value: Any) -> None: ...
    @overload
    def update(self, key: str, compartment: str, compartment2: str, value: Any) -> None: ...
    def update(self, key, compartment=None, compartment2=None, value=''):
        cdef string key_string
        cdef string value_string
        cdef int error

        if compartment == None and compartment2 == None:
            error = <int>self.ptr.updateFirst(
                key_string.assign(<const char*>key),
                value_string.assign(<const char*>value)
            )

        if compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            error = <int>self.ptr.updateFirst(
                key_string.assign(<const char*>key),
                _compartment, 
                value_string.assign(<const char*>value)
            )

        if compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            error = <int>self.ptr.updateFirst(
                key_string.assign(<const char*>key),
                _compartment, 
                _compartment2, 
                value_string.assign(<const char*>value)
            )

        if bool(error) == False:
            raise KeyError(key)

    @overload
    def set_expiry(self, key: str, seconds: int) -> None: ...
    @overload
    def set_expiry(self, key: str, compartment: str, seconds: int) -> None: ...
    @overload
    def set_expiry(self, key: str, compartment: str, compartment2: str, seconds: int) -> None: ...
    def set_expiry(self, key, compartment=None, compartment2=None, seconds=0):
        cdef string key_string
        cdef string _compartment
        cdef string _compartment2

        if compartment == None and compartment2 == None:
            self.ptr.setExpiry(key_string.assign(<const char*>key), <int32_t>seconds)

        if compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            self.ptr.setExpiry(key_string.assign(<const char*>key), _compartment, <int32_t>seconds)
            
        if compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            self.ptr.setExpiry(key_string.assign(<const char*>key), _compartment, _compartment2, <int32_t>seconds)

        return None

    @overload
    def resolve_single_match(self, var: str, list[VariableValue] l) -> None: ...
    @overload
    def resolve_single_match(self, var: str, compartment: str, list[VariableValue] l) -> None: ...
    @overload
    def resolve_single_match(self, var: str, compartment: str, compartment2: str, list[VariableValue] l) -> None: ...
    def resolve_single_match(self, var, compartment=None, compartment2=None, l=None):
        cdef string _var
        cdef string _compartment
        cdef string _compartment2
        cdef vector[const lib.VariableValue*] _list
        cdef VariableValue obj  # Deklarera VariableValue korrekt

        if len(l) != None:
            for obj in l:
                _ptr = obj.ptr
                if _ptr != NULL:
                    _list.push_back(<lib.VariableValue*>_ptr)

        if compartment == None and compartment2 == None:
            self.ptr.resolveSingleMatch(_var.assign(<const char*>var), &_list)

        if compartment != None and compartment2 == None:
            _compartment = compartment.encode()
            self.ptr.resolveSingleMatch(_var.assign(<const char*>var), _compartment, &_list)
            
        if compartment != None and compartment2 != None:
            _compartment = compartment.encode()
            _compartment2 = compartment2.encode()
            self.ptr.resolveSingleMatch(_var.assign(<const char*>var), _compartment, _compartment2, &_list)

        return None

    def __getitem__(self, key: str):
        return self.resolve(key)

    def __setitem__(self, key: str, value: str):
        self.store(key, value=value)

    def __delitem__(self, key: str):
        self.pop(key)

    def __dealloc__(self):
        del self.ptr

    def __repr__(self):
        return f"Collection('{self.name}', [...])"

    def __len__(self):
        return sizeof(self)


#   =======================================================================
#     Header Name:  modsecurity/collection/collections.h
#     Classes:
#       - Collections() = Cannot be constructed.
#   =======================================================================

cdef class Collections:

    cdef lib.Collections* ptr

    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)

    cdef void set_ptr(self, lib.Collections *ptr):
        self.ptr = ptr

    def __iter__(self):
        for key, col in self.__dict__.items():
            if key.endswith('_collection'):
                yield key, col

    def __dealloc__(self):
        del self.ptr

cdef Collections wrap_collections_class(lib.Collections *ptr):
    cdef Collections obj = Collections(_cinit_sentinel)
    cdef Collection _global_col = <Collection>wrap_collection_class(ptr.m_global_collection)
    cdef Collection _ip_col = <Collection>wrap_collection_class(ptr.m_ip_collection)
    cdef Collection _session_col = <Collection>wrap_collection_class(ptr.m_session_collection)
    cdef Collection _user_col = <Collection>wrap_collection_class(ptr.m_user_collection)
    cdef Collection _resource_col = <Collection>wrap_collection_class(ptr.m_resource_collection)

    obj.set_ptr(ptr)
    obj.global_collection = PyTuple_Pack(
        2,
        ptr.m_global_collection_key.c_str(), 
        <PyObject*>_global_col
    )
    obj.ip_collection = PyTuple_Pack(
        2,
        ptr.m_ip_collection_key.c_str(),
        <PyObject*>_ip_col
    )
    obj.session_collection = PyTuple_Pack(
        2,
        ptr.m_session_collection_key.c_str(),
        <PyObject*>_session_col
    )
    obj.user_collection = PyTuple_Pack(
        2,
        ptr.m_user_collection_key.c_str(), 
        <PyObject*>_user_col
    )
    obj.resource_collection = PyTuple_Pack(
        2,
        ptr.m_resource_collection_key.c_str(), 
        <PyObject*>_resource_col
    )

    return obj


#   =======================================================================
#     Header Name:  modsecurity/rules_exceptions.h
#     Classes:  RulesExceptions()
#
#     @IMPORTANT:  RulesExceptions cannot be constructed.
#   =======================================================================

# TODO: Bind more functions.

cdef RulesExceptions wrap_rules_exceptions(lib.RulesExceptions *ptr):
    cdef RulesExceptions obj = RulesExceptions(_cinit_sentinel)
    obj.ptr = ptr
    return obj

cdef class RulesExceptions:
    cdef lib.RulesExceptions *ptr

    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)
    def add_range(self, range: tuple[int, int]) -> None:
        a, b = range
        self.ptr.addRange(a, b)
    def add_number(self, value: int) -> None:
        self.ptr.addNumber(value)
    def __contains__(self, other: int) -> bool:
        return self.ptr.contains(other)


#   =======================================================================
#     Header Name:  modsecurity/rules_set.h
#     Classes:
#       - RulesSet()
#       - RulesSetProperties() = Unavailable at runtime.
#       - UnicodeMap()
#   =======================================================================

cdef bint config_boolean_to_bool(lib.RulesSet.ConfigBoolean value):
    if value == 0:
        return True
    elif value == 1:
        return False
    else:
        return False

cdef int config_int_to_int(lib.ConfigInt value):
    cdef int m_set = <int>value.m_set
    if m_set == 1:
        return value.m_value
    else:
        return 0

cdef str config_string_to_str(lib.ConfigString value):
    cdef int m_set = <int>value.m_set
    if value.m_value.empty() > 0:
        if m_set == 1:
            return value.m_value.c_str()
        else:
            return None
    else:
        return None

cdef float config_double_to_float(lib.ConfigDouble value):
    if value.m_set == 1:
        return value.m_value
    else:
        return 0.0

cpdef list unpack_array(_list[string] array):
    _sequence = list()
    for _string in array:
        _sequence.append(_string.c_str())
    return _sequence

cdef class UnicodeMap:
    cdef lib.UnicodeMapHolder *ptr
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)

    def __setitem__(self, index: int, value: int) -> int:
        self.change(index, value)

    def __getitem__(self, int index) -> int:
        value = <int&>self.ptr[index]
        return value

    def at(self, index: int) -> int:
        return self.ptr.at(index)

    def change(self, index: int, value: int) -> None:
        self.ptr.change(index, value)
cdef UnicodeMap wrap_unicode_map_table(lib.ConfigUnicodeMap ptr):
    cdef UnicodeMap obj

    if ptr.m_set > 0:
        obj = UnicodeMap(_cinit_sentinel)
        obj.ptr = ptr.m_unicodeMapTable.get()
        return obj
    return None

cpdef enum RuleEngine:
    DisabledRuleEngine,
    EnabledRuleEngine,
    DetectionOnlyRuleEngine,
    PropertyNotSetRuleEngine

cpdef enum BodyLimitAction:
    ProcessPartialBodyLimitAction,
    RejectBodyLimitAction,
    PropertyNotSetBodyLimitAction

cpdef enum OnFailedRemoteRulesAction:
    AbortOnFailedRemoteRulesAction,
    WarnOnFailedRemoteRulesAction,
    PropertyNotSetRemoteRulesAction

cdef class RulesSet:

    cdef lib.RulesSet *ptr

    @property
    def audit_log(self) -> AuditLog:
        return wrap_audit_log(self.ptr.m_auditLog)
    @property
    def request_body_limit_action(self):
        """Defines the action taken when the request body limit is reached."""
        return <BodyLimitAction>self.ptr.m_requestBodyLimitAction

    @property
    def response_body_limit_action(self):
        """Defines the action taken when the response body limit is reached."""
        return <BodyLimitAction>self.ptr.m_responseBodyLimitAction

    @property
    def sec_request_body_access(self):
        """Determines whether request body access is enabled."""
        return config_boolean_to_bool(self.ptr.m_secRequestBodyAccess)

    @property
    def sec_response_body_access(self):
        """Determines whether response body access is enabled."""
        return config_boolean_to_bool(self.ptr.m_secResponseBodyAccess)

    @property
    def sec_xml_external_entity(self):
        """Controls XML external entity processing."""
        return config_boolean_to_bool(self.ptr.m_secXMLExternalEntity)

    @property
    def tmp_save_uploaded_files(self):
        """Specifies whether uploaded files should be temporarily saved."""
        return config_boolean_to_bool(self.ptr.m_tmpSaveUploadedFiles)

    @property
    def upload_keep_files(self):
        """Determines if uploaded files should be kept."""
        return config_boolean_to_bool(self.ptr.m_uploadKeepFiles)

    @property
    def arguments_limit(self):
        """Maximum allowed number of arguments in a request."""
        return config_double_to_float(self.ptr.m_argumentsLimit)

    @property
    def request_body_json_depth_limit(self):
        """Maximum depth allowed for JSON request bodies."""
        return config_double_to_float(self.ptr.m_requestBodyJsonDepthLimit)

    @property
    def request_body_limit(self):
        """Maximum size of the request body."""
        return config_double_to_float(self.ptr.m_requestBodyLimit)

    @property
    def request_body_no_files_limit(self):
        """Maximum request body size when no files are uploaded."""
        return config_double_to_float(self.ptr.m_requestBodyNoFilesLimit)

    @property
    def response_body_limit(self):
        """Maximum size of the response body."""
        return config_double_to_float(self.ptr.m_responseBodyLimit)

    @property
    def pcre_match_limit(self):
        """Limits the number of PCRE (regex) matches allowed."""
        return config_int_to_int(self.ptr.m_pcreMatchLimit)

    @property
    def upload_file_limit(self):
        """Maximum number of uploaded files allowed."""
        return config_int_to_int(self.ptr.m_uploadFileLimit)

    @property
    def upload_file_mode(self):
        """File mode for uploaded files."""
        return config_int_to_int(self.ptr.m_uploadFileMode)

    @property
    def debug_log(self):
        """Pointer to the debug log configuration."""
        return wrap_debug_log(self.ptr.m_debugLog)

    @property
    def remote_rules_action_on_failed(self):
        """Specifies the action taken when remote rules fail."""
        return <OnFailedRemoteRulesAction>self.ptr.m_remoteRulesActionOnFailed

    @property
    def sec_rule_engine(self):
        """Defines the rule engine behavior."""
        return <RuleEngine>self.ptr.m_secRuleEngine

    @property
    def exceptions(self):
        """Manages exceptions in rule processing."""
        return wrap_rules_exceptions(&self.ptr.m_exceptions)

    @property
    def components(self):
        """List of component identifiers."""
        return unpack_array(self.ptr.m_components)

    @property
    def response_body_type_to_be_inspected(self):
        """Specifies the types of response bodies to inspect."""

        cdef lib.ConfigSet obj = self.ptr.m_responseBodyTypeToBeInspected
        if obj.m_set > 0:
            _value = set()

            for _string in obj.m_value:
                _value.add(_string.c_str())
            return _value
        return set()

    @property
    def httpbl_key(self):
        """Stores the HTTP blacklist (HTTPBL) API key."""
        return config_string_to_str(self.ptr.m_httpblKey)

    @property
    def upload_directory(self):
        """Directory path for storing uploaded files."""
        return config_string_to_str(self.ptr.m_uploadDirectory)

    @property
    def upload_tmp_directory(self):
        """Temporary directory for uploaded files."""
        return config_string_to_str(self.ptr.m_uploadTmpDirectory)

    @property
    def sec_argument_separator(self):
        """Character used to separate arguments in a request."""
        return config_string_to_str(self.ptr.m_secArgumentSeparator)

    @property
    def sec_web_app_id(self):
        """Identifier for the web application."""
        return config_string_to_str(self.ptr.m_secWebAppId)

    @property
    def unicode_map_table(self):
        """Configuration for Unicode mapping tables."""
        return wrap_unicode_map_table(self.ptr.m_unicodeMapTable)

    def __cinit__(self):
        self.ptr = new lib.RulesSet()

    cdef lib.RulesSet* get_ptr(self):
        return self.ptr

    def load_from_uri(self, file: str):
        return self.error_check(self.ptr.loadFromUri(file))
    
    def merge(self, RulesSet source):
        return self.error_check(self.ptr.merge(source.ptr))

    def dump(self):
        self.ptr.dump()

    def load_from_remote(self, key: str, uri: str):
        return self.error_check(self.ptr.loadRemote(key, uri))

    def load_from_plaintext(self, plaintext: str):
        return self.error_check(self.ptr.load(plaintext))

    cpdef int error_check(self, int error):
        if (error <= 0):
            parser_error = <string>self.ptr.getParserError()
            error_string_size = <int>parser_error.size()
            if error_string_size != 0:
                error_msg = parser_error.c_str()
            else:
                error_msg = 'Could not load any rules.'
            raise RulesSetError(code=error, log=error_msg)
        return error

    def __dealloc__(self):
        del self.ptr


#   =======================================================================
#     Header Name:  modsecurity/rule_message.h
#     Classes:
#       - RuleMessage() = Cannot be constructed.
#
#     Enumerators:
#       - LogMessageInfo
#   =======================================================================

class LogMessageInfo(IntEnum):
    ErrorLogTailLogMessageInfo = 2
    ClientLogMessageInfo = 4

cdef class RuleMessage:

    cdef const lib.RuleMessage *ptr
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)

    cdef void _init(self, const lib.RuleMessage *ptr):
        self.ptr = ptr

    @overload
    def log(self) -> str: ...
    @overload
    def log(self, props: LogMessageInfo) -> str: ...
    @overload
    def log(self, props: LogMessageInfo, response_code: int) -> str: ...
    def log(self, props=None, response_code=None):
        
        if props == None and response_code == None:
            return self.ptr.log().c_str()
        elif props != None and response_code == None:
            return self.ptr.log(int(props)).c_str()
        else:
            return self.ptr.log(int(props), int(response_code)).c_str()

    def error_log(self):
        return self.ptr.errorLog().c_str()
    
    def get_phase(self):
        return self.ptr.getPhase()

    def __dealloc__(self):
        del self.ptr

cpdef list _convert_to_py_list(_list[string] array):
    _tags = []
    cdef _list[string].iterator array_iterator
    for _string in array:
        _tags.append(_string.c_str())

    return _tags

cdef RuleMessage wrap_rule_message_ptr(const lib.RuleMessage *ptr):
    cdef RuleMessage obj = RuleMessage(_cinit_sentinel)
    obj._init(ptr)
    obj.data = ptr.m_data.c_str()
    obj.is_disruptive = bool(<int>ptr.m_isDisruptive)
    obj.match = ptr.m_match.c_str()
    obj.message = ptr.m_message.c_str()
    obj.no_audit_log = bool(<int>ptr.m_noAuditLog)
    obj.reference = ptr.m_reference.c_str()
    obj.save_message = bool(<int>ptr.m_saveMessage)
    obj.severity = ptr.m_severity
    obj.tags = _convert_to_py_list(ptr.m_tags)
    return obj
    
    
#   =======================================================================
#     Header Name:  modsecurity/modsecurity.h
#     Classes:
#       - ModSecurity()
#
#     Enumerators:
#       - LogProperty
#   =======================================================================

cdef void _c_callback_rm(void* data, const void* log) noexcept nogil:
    # Förvärva GIL innan Python-kod anropas

    with gil:
        (<object>data)._log_cb(wrap_rule_message_ptr(<const lib.RuleMessage*>log))

cdef void _c_callback_str(void* data, const void* log) noexcept nogil:
    # Förvärva GIL innan Python-kod anropas

    with gil:
        (<object>data)._log_cb(<object>log)

cdef class ModSecurity:

    cdef lib.ModSecurity *ptr  # Lägg till pekarvariabel här
    cdef public object _transactions
    cdef object _log_cb

    @property
    def global_collection(self):
        return wrap_collection_class(self.ptr.m_global_collection)
    @property
    def resource_collection(self):
        return wrap_collection_class(self.ptr.m_resource_collection)
    @property
    def ip_collection(self):
        return wrap_collection_class(self.ptr.m_ip_collection)
    @property
    def session_collection(self):
        return wrap_collection_class(self.ptr.m_session_collection)
    @property
    def user_collection(self):
        return wrap_collection_class(self.ptr.m_user_collection)
    def __cinit__(self):
        self.ptr = new lib.ModSecurity()
        self._transactions = set()

    def who_am_i(self):
        data = self.ptr.whoAmI().c_str()
        return data

    def set_connector_info(self, connector: str):
        cdef string connector_string
        self.ptr.setConnectorInformation(connector_string.assign(<const char*>connector))

    def get_connector_info(self):
        connector = self.ptr.getConnectorInformation().c_str()
        return connector

    @overload
    def set_log_cb(self, log_cb: Callable): ...
    @overload
    def set_log_cb(self, log_cb: Callable, properties: int): ...
    def set_log_cb(self, log_cb, properties=0):
        assert callable(log_cb) and isinstance(log_cb, Callable)

        if properties > 0:
            if properties == LogProperty.RuleMessageLogProperty:
                self.ptr.setServerLogCb(
                    <lib.ModSecLogCb>_c_callback_rm,
                    properties
                )

            else:
                if properties > lib.LogProperty.RuleMessageLogProperty:
                    raise ValueError('properties argument out of range.')
                self.ptr.setServerLogCb(
                    <lib.ModSecLogCb>_c_callback_str,
                    properties
                )
        else:
            if properties < 0:
                raise ValueError('properties argument out of range.')
            self.ptr.setServerLogCb(<lib.ModSecLogCb>_c_callback_str)

        self._log_cb = log_cb

    def __dealloc__(self):
        del self.ptr

def init():
    return ModSecurity()


#   =======================================================================
#     Header Name:  modsecurity/debug_log.h
#     Classes:
#       - DebugLog() = Cannot be constructed.
#   =======================================================================

cdef DebugLog wrap_debug_log(lib.DebugLog *ptr):
    cdef DebugLog obj = DebugLog(_cinit_sentinel)
    obj.ptr = ptr
    return obj

cdef class DebugLog:
    cdef lib.DebugLog *ptr

    @property
    def debug_level(self) -> int:
        return self.ptr.m_debugLevel
    def __cinit__(self, sentinel) -> None:
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)

    def is_log_file_set(self) -> bool:
        return self.ptr.isLogFileSet()
    
    def is_log_level_set(self) -> bool:
        return self.ptr.isLogLevelSet()

    def set_debug_log_level(self, level: int) -> None:
        return self.ptr.setDebugLogLevel(level)

    def set_debug_log_file(self, filename: str) -> None:
        cdef string error
        cdef string _filename
        self.ptr.setDebugLogFile(_filename.assign(<const char*>filename), &error)

        if error.empty() < 1:
            raise ModSecurityError(error.c_str())

    def get_debug_log_file(self) -> str:
        return self.ptr.getDebugLogFile().c_str()

    def get_debug_log_level(self) -> int:
        return self.ptr.getDebugLogLevel()


#   =======================================================================
#     Header Name:  modsecurity/audit_log.h
#     Classes:
#       - AuditLog() = Cannot be constructed.
#   =======================================================================

cdef AuditLog wrap_audit_log(lib.AuditLog *ptr):
    cdef AuditLog obj = AuditLog(_cinit_sentinel)
    obj.ptr = ptr
    return obj

cpdef enum AuditLogType:
    NotSetAuditLogType
    SerialAuditLogType
    ParallelAuditLogType
    HttpsAuditLogType

cpdef enum AuditLogStatus:
    NotSetLogStatus
    OnAuditLogStatus
    OffAuditLogStatus
    RelevantOnlyAuditLogStatus

cpdef enum AuditLogFormat:
    NotSetAuditLogFormat
    JSONAuditLogFormat
    NativeAuditLogFormat

cpdef enum AuditLogParts:
    AAuditLogPart = 2
    BAuditLogPart = 4
    CAuditLogPart = 8
    DAuditLogPart = 16
    EAuditLogPart = 32
    FAuditLogPart = 64
    GAuditLogPart = 128
    HAuditLogPart = 256
    IAuditLogPart = 512
    JAuditLogPart = 1024
    KAuditLogPart = 2048
    ZAuditLogPart = 4096

cdef class AuditLog:
        
    cdef lib.AuditLog *ptr

    @property
    def path1(self) -> str:
        return self.ptr.m_path1.c_str()

    @property
    def path2(self) -> str:
        return self.ptr.m_path2.c_str()

    @property
    def storage_dir(self) -> str:
        return self.ptr.m_storage_dir.c_str()

    @property
    def format(self) -> AuditLogFormat:
        return AuditLogFormat(self.ptr.m_format)

    def __cinit__(self, sentinel) -> None:
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)

    def set_storage_dir_mode(self, permission: int) -> None:
        self.ptr.setStorageDirMode(permission)

    def set_file_mode(self, permission: int) -> None:
        self.ptr.setFileMode(permission)

    def set_status(self, AuditLogStatus new_status) -> None:
        self.ptr.setStatus(new_status)

    def set_relevant_status(self, new_relevant_status: str) -> None:
        cdef string _new_relevant_status
        self.ptr.setRelevantStatus(_new_relevant_status.assign(<const char*>new_relevant_status))

    def set_file_path1(self, path: str) -> None:
        cdef string _path
        self.ptr.setFilePath1(_path.assign(<const char*>path))

    def set_file_path2(self, path: str) -> None:
        cdef string _path
        self.ptr.setFilePath2(_path.assign(<const char*>path))

    def set_storage_dir(self, path: str) -> None:
        cdef string _path
        self.ptr.setStorageDir(_path.assign(<const char*>path))

    def set_format(self, AuditLogFormat fmt) -> bool:
        self.ptr.setFormat(fmt)

    def get_directory_permission(self) -> int:
        return self.ptr.getDirectoryPermission()

    def get_file_permission(self) -> int:
        return self.ptr.getFilePermission()

    def get_parts(self) -> int:
        return self.ptr.getParts()

    def set_parts(self, new_parts: str) -> None:
        cdef string _new_parts
        self.ptr.setParts(_new_parts.assign(<const char*>new_parts))

    def set_type(self, AuditLogType audit_type) -> None:
        self.ptr.setType(audit_type)

    def save_if_relevant(self, Transaction transaction, parts: int = -1) -> bool:
        if parts == -1:
            return self.ptr.saveIfRelevant(transaction.ptr)
        return self.ptr.saveIfRelevant(transaction.ptr, parts)

    def is_relevant(self, status: int) -> bool:
        return self.ptr.isRelevant(status)

    @staticmethod
    def add_parts(parts: int, new_parts: str) -> int:
        cdef string _new_parts
        return lib.AuditLog.addParts(parts, _new_parts.assign(<const char*>new_parts))

    @staticmethod
    def remove_parts(parts: int, new_parts: str) -> int:
        cdef string _new_parts
        return lib.AuditLog.removeParts(parts, _new_parts.assign(<const char*>new_parts))

    def set_ctl_audit_engine_active(self) -> None:
        self.ptr.setCtlAuditEngineActive()

    def __dealloc__(self):
        del self.ptr


#   =======================================================================
#     Header Name:  modsecurity/anchored_set_variable.h
#     Classes:
#       - AnchoredSetVariable() = Cannot be constructed.
#   =======================================================================

cdef AnchoredSetVariable wrap_anchored_set_variable(lib.AnchoredSetVariable *ptr):
    cdef AnchoredSetVariable obj = AnchoredSetVariable(_cinit_sentinel)
    obj.ptr = ptr
    return obj
    
cdef class AnchoredSetVariable:
    cdef lib.AnchoredSetVariable *ptr
    @property
    def name(self):
        return self.ptr.m_name.c_str()
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)
    @overload
    def set(self, key: str, value: str, offset: int) -> None: ...
    @overload
    def set(self, key: str, value: str, offset: int, len: int) -> None: ...
    def set(self, key, value, offset, len=0):
        cdef string _key
        cdef string _value
        if len > 0:
            self.ptr.set(_key.assign(<const char*>key), _value.assign(<const char*>value), <size_t>offset, <size_t>len)
        else:
            self.ptr.set(_key.assign(<const char*>key), _value.assign(<const char*>value), <size_t>offset)
    def resolve_first(self, key: str):
        cdef string _key
        cdef string *value = self.ptr.resolveFirst(_key.assign(<const char*>key)).get()
        if value != NULL:
            return value.c_str()
        return None


#   =======================================================================
#     Header Name:  modsecurity/anchored_variable.h
#     Classes:
#       - AnchoredVariable() = Cannot be constructed.
#   =======================================================================

cdef AnchoredVariable wrap_anchored_variable(lib.AnchoredVariable *ptr):
    cdef AnchoredVariable obj = AnchoredVariable(_cinit_sentinel)
    obj.ptr = ptr
    return obj
    
cdef class AnchoredVariable:
    cdef lib.AnchoredVariable *ptr
    @property
    def name(self):
        return self.ptr.m_name.c_str()
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)
    @overload
    def set(self, key: str, offset: int) -> None: ...
    @overload
    def set(self, key: str, offset: int, offset_len: int) -> None: ...
    def set(self, key, offset, offset_len=0):
        cdef string _key
        if offset_len > 0:
            self.ptr.set(_key.assign(<const char*>key), <size_t>offset, <size_t>offset_len)
        else:
            self.ptr.set(_key.assign(<const char*>key), <size_t>offset)
    def resolve_first(self):
        cdef string *value = self.ptr.resolveFirst().get()
        if value != NULL:
            return value.c_str()
        return None


#   =======================================================================
#     Header Name:  modsecurity/anchored_set_variable_translation_proxy.h
#     Classes:
#       - AnchoredSetVariableTranslationProxy() = Cannot be constructed.
#   =======================================================================

cdef AnchoredSetVariableTranslationProxy wrap_anchored_set_variable_translation_proxy(lib.AnchoredSetVariableTranslationProxy *ptr):
    cdef AnchoredSetVariableTranslationProxy obj = AnchoredSetVariableTranslationProxy(_cinit_sentinel)
    obj.ptr = ptr
    return obj
    
cdef class AnchoredSetVariableTranslationProxy:
    cdef lib.AnchoredSetVariableTranslationProxy *ptr
    @property
    def name(self):
        return self.ptr.m_name.c_str()
    def __cinit__(self, sentinel):
        if sentinel is not _cinit_sentinel:
            raise _create_construction_error(self.__class__.__name__)
    def resolve_first(self, key: str):
        cdef string _key
        cdef string *value = self.ptr.resolveFirst(_key.assign(<const char*>key)).get()
        if value != NULL:
            return value.c_str()
        return None

        
#   =======================================================================
#     Header Name:  modsecurity/transaction.h
#     Classes:
#       - TransactionAnchoredVariables() = Unavailable at runtime.
#       - Transaction()
#   =======================================================================

cdef class Transaction:
    """
    Description
    -----------
    Represents the inspection on an entire request. An instance of the Transaction class represents an request, on its different phases.
    """

    cdef lib.Transaction *ptr
    cdef ModSecurity _msc
    cdef RulesSet _rules_set

    @property
    def id(self):
        """Returns an `str` with the id of this transaction."""
        return self.ptr.m_id.c_str()
    @property
    def uri(self):
        """Returns an `str` with the request uri of this transaction."""
        return self.ptr.m_uri.c_str()
    @property
    def request_body_type(self):
        """Returns an instance of `modsecurity.RequestBodyType` describing the request body type."""
        return RequestBodyType(int(self.ptr.m_requestBodyType))
    @property
    def request_body_processor(self):
        """Returns an instance of `modsecurity.RequestBodyType` describing the request body processor."""
        return RequestBodyType(int(self.ptr.m_requestBodyProcessor))
    @property
    def msc(self):
        """Returns the current instance of `modsecurity.ModSecurity`."""
        return self._msc
    @property
    def collections(self):
        """Returns a `modsecurity.Collections` instance with a set of `modsecurity.Collection` instances."""
        return wrap_collections_class(<lib.Collections*>(&self.ptr.m_collections))
    @property
    def rules_set(self):
        """Returns the `RulesSet` instance that was used for this transaction."""
        return self._rules_set

    @property
    def rule_messages(self):
        cdef _list[lib.RuleMessage] *rule_messages = &self.ptr.m_rulesMessages
        cdef int rule_messages_size = <int>rule_messages.size()
        _rule_messages = []
        if rule_messages_size > 0:
            for i in range(rule_messages_size):
                rule_message = <lib.RuleMessage*>&rule_messages[i]
                _rule_messages.append(wrap_rule_message_ptr(<const lib.RuleMessage*>rule_message))
        return _rule_messages

    @property
    def actions(self):
        return create_intervention_instances(self.ptr.m_actions)

    @property
    def variableRequestHeadersNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableRequestHeadersNames)

    @property
    def variableResponseContentType(self):
        return wrap_anchored_variable(&self.ptr.m_variableResponseContentType)

    @property
    def variableResponseHeadersNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableResponseHeadersNames)

    @property
    def variableARGScombinedSize(self):
        return wrap_anchored_variable(&self.ptr.m_variableARGScombinedSize)

    @property
    def variableAuthType(self):
        return wrap_anchored_variable(&self.ptr.m_variableAuthType)

    @property
    def variableFilesCombinedSize(self):
        return wrap_anchored_variable(&self.ptr.m_variableFilesCombinedSize)

    @property
    def variableFullRequest(self):
        return wrap_anchored_variable(&self.ptr.m_variableFullRequest)

    @property
    def variableFullRequestLength(self):
        return wrap_anchored_variable(&self.ptr.m_variableFullRequestLength)

    @property
    def variableInboundDataError(self):
        return wrap_anchored_variable(&self.ptr.m_variableInboundDataError)

    @property
    def variableMatchedVar(self):
        return wrap_anchored_variable(&self.ptr.m_variableMatchedVar)

    @property
    def variableMatchedVarName(self):
        return wrap_anchored_variable(&self.ptr.m_variableMatchedVarName)

    @property
    def variableMscPcreError(self):
        return wrap_anchored_variable(&self.ptr.m_variableMscPcreError)

    @property
    def variableMscPcreLimitsExceeded(self):
        return wrap_anchored_variable(&self.ptr.m_variableMscPcreLimitsExceeded)

    @property
    def variableMultipartBoundaryQuoted(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartBoundaryQuoted)

    @property
    def variableMultipartBoundaryWhiteSpace(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartBoundaryWhiteSpace)

    @property
    def variableMultipartCrlfLFLines(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartCrlfLFLines)

    @property
    def variableMultipartDataAfter(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartDataAfter)

    @property
    def variableMultipartDataBefore(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartDataBefore)

    @property
    def variableMultipartFileLimitExceeded(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartFileLimitExceeded)

    @property
    def variableMultipartHeaderFolding(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartHeaderFolding)

    @property
    def variableMultipartInvalidHeaderFolding(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartInvalidHeaderFolding)

    @property
    def variableMultipartInvalidPart(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartInvalidPart)

    @property
    def variableMultipartInvalidQuoting(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartInvalidQuoting)


    @property
    def variableMultipartLFLine(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartLFLine)

    @property
    def variableMultipartMissingSemicolon(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartMissingSemicolon)

    @property
    def variableMultipartStrictError(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartStrictError)

    @property
    def variableMultipartUnmatchedBoundary(self):
        return wrap_anchored_variable(&self.ptr.m_variableMultipartUnmatchedBoundary)

    @property
    def variableOutboundDataError(self):
        return wrap_anchored_variable(&self.ptr.m_variableOutboundDataError)

    @property
    def variablePathInfo(self):
        return wrap_anchored_variable(&self.ptr.m_variablePathInfo)

    @property
    def variableQueryString(self):
        return wrap_anchored_variable(&self.ptr.m_variableQueryString)

    @property
    def variableRemoteAddr(self):
        return wrap_anchored_variable(&self.ptr.m_variableRemoteAddr)

    @property
    def variableRemoteHost(self):
        return wrap_anchored_variable(&self.ptr.m_variableRemoteHost)

    @property
    def variableRemotePort(self):
        return wrap_anchored_variable(&self.ptr.m_variableRemotePort)

    @property
    def variableReqbodyError(self):
        return wrap_anchored_variable(&self.ptr.m_variableReqbodyError)

    @property
    def variableReqbodyErrorMsg(self):
        return wrap_anchored_variable(&self.ptr.m_variableReqbodyErrorMsg)

    @property
    def variableReqbodyProcessorError(self):
        return wrap_anchored_variable(&self.ptr.m_variableReqbodyProcessorError)

    @property
    def variableReqbodyProcessorErrorMsg(self):
        return wrap_anchored_variable(&self.ptr.m_variableReqbodyProcessorErrorMsg)

    @property
    def variableReqbodyProcessor(self):
        return wrap_anchored_variable(&self.ptr.m_variableReqbodyProcessor)

    @property
    def variableRequestBasename(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestBasename)

    @property
    def variableRequestBody(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestBody)

    @property
    def variableRequestBodyLength(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestBodyLength)

    @property
    def variableRequestFilename(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestFilename)

    @property
    def variableRequestLine(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestLine)

    @property
    def variableRequestMethod(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestMethod)

    @property
    def variableRequestProtocol(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestProtocol)

    @property
    def variableRequestURI(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestURI)

    @property
    def variableRequestURIRaw(self):
        return wrap_anchored_variable(&self.ptr.m_variableRequestURIRaw)

    @property
    def variableResource(self):
        return wrap_anchored_variable(&self.ptr.m_variableResource)

    @property
    def variableResponseBody(self):
        return wrap_anchored_variable(&self.ptr.m_variableResponseBody)

    @property
    def variableResponseContentLength(self):
        return wrap_anchored_variable(&self.ptr.m_variableResponseContentLength)

    @property
    def variableResponseProtocol(self):
        return wrap_anchored_variable(&self.ptr.m_variableResponseProtocol)

    @property
    def variableResponseStatus(self):
        return wrap_anchored_variable(&self.ptr.m_variableResponseStatus)

    @property
    def variableServerAddr(self):
        return wrap_anchored_variable(&self.ptr.m_variableServerAddr)

    @property
    def variableServerName(self):
        return wrap_anchored_variable(&self.ptr.m_variableServerName)

    @property
    def variableServerPort(self):
        return wrap_anchored_variable(&self.ptr.m_variableServerPort)

    @property
    def variableSessionID(self):
        return wrap_anchored_variable(&self.ptr.m_variableSessionID)

    @property
    def variableUniqueID(self):
        return wrap_anchored_variable(&self.ptr.m_variableUniqueID)

    @property
    def variableUrlEncodedError(self):
        return wrap_anchored_variable(&self.ptr.m_variableUrlEncodedError)

    @property
    def variableUserID(self):
        return wrap_anchored_variable(&self.ptr.m_variableUserID)

    @property
    def variableArgs(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableArgs)

    @property
    def variableArgsGet(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableArgsGet)

    @property
    def variableArgsPost(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableArgsPost)

    @property
    def variableFilesSizes(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableFilesSizes)

    @property
    def variableFilesNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableFilesNames)

    @property
    def variableFilesTmpContent(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableFilesTmpContent)

    @property
    def variableMultipartFileName(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableMultipartFileName)

    @property
    def variableMultipartName(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableMultipartName)

    @property
    def variableMatchedVarsNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableMatchedVarsNames)

    @property
    def variableMatchedVars(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableMatchedVars)

    @property
    def variableFiles(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableFiles)

    @property
    def variableRequestCookies(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableRequestCookies)

    @property
    def variableRequestHeaders(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableRequestHeaders)

    @property
    def variableResponseHeaders(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableResponseHeaders)

    @property
    def variableGeo(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableGeo)

    @property
    def variableRequestCookiesNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableRequestCookiesNames)

    @property
    def variableFilesTmpNames(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableFilesTmpNames)

    @property
    def variableMultipartPartHeaders(self):
        return wrap_anchored_set_variable(&self.ptr.m_variableMultipartPartHeaders)

    @property
    def variableArgsNames(self):
        return wrap_anchored_set_variable_translation_proxy(&self.ptr.m_variableArgsNames)

    @property
    def variableArgsGetNames(self):
        return wrap_anchored_set_variable_translation_proxy(&self.ptr.m_variableArgsGetNames)

    @property
    def variableArgsPostNames(self):
        return wrap_anchored_set_variable_translation_proxy(&self.ptr.m_variableArgsPostNames)
        
    def __cinit__(self, ModSecurity msc, RulesSet rules_set, id: str | None = None):
        """
        Initializes a transaction.
        """
        if id:
            self.ptr = new lib.Transaction(msc.ptr, rules_set.ptr, id, <void*>msc._log_cb if msc._log_cb else NULL)
        else:
            self.ptr = new lib.Transaction(msc.ptr, rules_set.ptr, <void*>msc._log_cb if msc._log_cb else NULL)

        self._msc = msc
        self._rules_set = rules_set

    def to_old_audit_log_format(self, parts: int, trailer: str):
        """
        Convert the transaction instance to a str.

        Args:
            parts (int): Audit log parts
        """
        
        cdef string _trailer
        return self.ptr.toOldAuditLogFormat(parts, _trailer.assign(<const char*>trailer)).c_str()

    def to_dict(self, parts: int):
        """
        Convert the transaction instance to a dict. This function is the same as `.toJSON()`.

        Args:
            parts (int): Audit log parts
        """
        try:
            return json.loads(self.ptr.toJSON(parts).c_str())
        except json.JSONDecodeError:
            raise TransactionError('Could not deserialize json data')
    def process_connection(self, remote_addr: str, remote_port: int, server_addr: str, server_port: int):
        self.ptr.processConnection(
            remote_addr, 
            remote_port, 
            server_addr, 
            server_port
        )

    def process_uri(self, uri: str, protocol: str, version: str):
        self.ptr.processURI(
            uri,
            protocol,
            version
        )

    def process_request_headers(self):
        self.ptr.processRequestHeaders()

    def add_request_header(self, key: str, value: str):
        cdef string _key
        cdef string _value

        _key.assign(<const char*>key)
        _value.assign(<const char*>value)

        self.ptr.addRequestHeader(
            _key,
            _value
        )

    def process_request_body(self):
        self.ptr.processRequestBody()

    def process_response_headers(self, status: int, protocol: str):
        cdef string protocol_string
        self.ptr.processResponseHeaders(status, protocol_string.assign(<const char*>protocol))

    def process_logging(self):
        self.ptr.processLogging()

    def append_request_body(self, body: bytes | bytearray | memoryview):
        if isinstance(body, bytearray):
            body = bytes(body)
        if isinstance(body, memoryview):
            body = body.tobytes()

        cdef string _body
        _body.assign(<const char*>body)
        
        bool_error_check(self.ptr.appendRequestBody(<const unsigned char*>_body.c_str(), <size_t>_body.size()), self.id, log='Could not append request body: See debug log for more information.')

    def append_request_body_from_file(self, file: str):
        bool_error_check(
            self.ptr.requestBodyFromFile(file),
            self.id,
            log=f'Could not append request body from file {file}: See debug log for more information.'
        )

    def add_response_header(self, key: str, value: str):
        cdef string _key
        cdef string _value

        _key.assign(<const char*>key)
        _value.assign(<const char*>value)
        self.ptr.addResponseHeader(
            _key,
            _value
        )

    def process_response_body(self):
        self.ptr.processResponseBody()

    def append_response_body(self, body: bytes | bytearray | memoryview):
        if isinstance(body, bytearray):
            body = bytes(body)
        if isinstance(body, memoryview):
            body = body.tobytes()

        cdef string _body
        _body.assign(<const char*>body)
        
        bool_error_check(
            self.ptr.appendResponseBody(<const unsigned char*>_body.c_str(), <size_t>_body.size()),
            self.id,
            log=f'Could not append response body: See debug log for more information.'
        )
            
    def intervention(self):
        cdef lib.ModSecurityIntervention* intervention = <lib.ModSecurityIntervention*>malloc(sizeof(lib.ModSecurityIntervention))
        error = self.ptr.intervention(intervention)
        if error == 1:
            i = create_msc_intervention()
            try:
                i.status = intervention.status
                i.pause = intervention.pause
                i.log = intervention.log.decode('utf-8') if intervention.log != NULL else None
                i.url = intervention.url.decode('utf-8') if intervention.url != NULL else None
                i.disruptive = intervention.disruptive
            finally:
                _msc_intervention_free(intervention)
                intervention = NULL
            return i
        else:
            return None

    def get_response_body(self):
        body = self.ptr.getResponseBody()
        return body

    def get_response_body_length(self):
        cdef size_t response_body_size = <size_t>self.ptr.getResponseBodyLength()
        return <int>response_body_size

    def get_request_body_length(self):
        cdef size_t request_body_size = <size_t>self.ptr.getRequestBodyLength()
        return <int>request_body_size

    def update_status_code(self, status: int):
        self.ptr.updateStatusCode(status)

    def set_request_hostname(self, hostname: str):
        cdef string _hostname
        self.ptr.setRequestHostName(_hostname.assign(<const char*>hostname))

    def get_rule_engine_state(self):
        return self.ptr.getRuleEngineState()

    def __dealloc__(self):
        if self in self.msc._transactions:
            self.msc._transactions.remove(self)
        del self.ptr

    def __repr__(self):
        return f'<modsecurity.{self.__class__.__name__} "id={self.id}" >'