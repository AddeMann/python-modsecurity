from typing import TypeVar, TypeAlias, Callable, overload, Union, Generic, Iterator, Any, Collection as _Collection, Sequence

from _typeshed import StrOrBytesPath, ReadableBuffer

from enum import IntEnum

_T = TypeVar('_T')
_UT = TypeVar('_UT', bound=int)
_UT_co = TypeVar('_T_co', bound=int, default=int, covariant=True)
_T2 = TypeVar('_T2')
_KT = TypeVar('_KT')
_VT = TypeVar('_VT')
_ColNameType = TypeVar('_ColNameType', bound=str, covariant=True)
_T_CollectionKey = TypeVar('_T_CollectionKey', bound=str, default=str, covariant=True)
_T_CollectionCls = TypeVar('_T_CollectionCls', bound=Collection[str], default=Collection[str], covariant=True)
_LogCbFunc: TypeAlias = Callable[[str | RuleMessage], None]
LogCbFunc = TypeVar('LogCbFunc', bound=_LogCbFunc)

__version__: str

class RulesSetError(RuntimeError): ...
        
class TransactionError(RuntimeError): ...
class Phases(IntEnum):
    ConnectionPhase: int
    UriPhase: int
    RequestHeadersPhase: int
    RequestBodyPhase: int
    ResponseHeadersPhase: int
    ResponseBodyPhase: int
    LoggingPhase: int
    NUMBER_OF_PHASES: int
    
class LogProperty(IntEnum):
    TextLogProperty: int
    RuleMessageLogProperty: int
    IncludeFullHighlightLogProperty: int
    
TextLogProperty: int
RuleMessageLogProperty: int
IncludeFullHighlightLogProperty: int

class LogMessageInfo(IntEnum):
    ErrorLogTailLogMessageInfo: int
    ClientLogMessageInfo: int
    
class RequestBodyType(IntEnum):
    UnknownFormat: int
    MultiPartRequestBody: int
    WWWFormUrlEncoded: int
    JSONRequestBody: int
    XMLRequestBody: int

class VariableValue:
    @overload
    def __init__(self, key: _KT, value: _VT) -> None: ...
    @overload
    def __init__(self, collection: _T, key: _KT, value: _VT) -> None: ...
    def get_key(self) -> _KT: ...
    def get_key_with_collection(self) -> str: ...
    def get_collection(self) -> _T: ...
    def get_value(self) -> _VT: ...
    def set_value(self, value: _VT) -> None: ...
    def reserve_origin(self, additional_size: int) -> None: ...
    
class Collection(Generic[_ColNameType]):
    name: str
    @overload
    def resolve(self, key: _KT, /) -> _VT | None: ...
    @overload
    def resolve(self, key: _KT, compartment: _T) -> _VT | None: ...
    @overload
    def resolve(self, key: _KT, compartment: _T, compartment2: _T2) -> _VT | None: ...
    @overload
    def store(self, key: _KT, value: _VT) -> None: ...
    @overload
    def store(self, key: _KT, compartment: _T, value: _VT) -> None: ...
    @overload
    def store(self, key: _KT, compartment: _T, compartment2: _T2, value: _VT) -> None: ...
    @overload
    def update(self, key: _KT, value: _VT) -> None: ...
    @overload
    def update(self, key: _KT, compartment: _T, value: _VT) -> None: ...
    @overload
    def update(self, key: _KT, compartment: _T, compartment2: _T2, value: _VT) -> None: ...
    @overload
    def set_expiry(self, key: _KT, seconds: int = 4) -> None: ...
    @overload
    def set_expiry(self, key: _KT, compartment: _T, seconds: int = 4) -> None: ...
    @overload
    def set_expiry(self, key: _KT, compartment: _T, compartment2: _T2, seconds: int = 4) -> None: ...
    @overload
    def pop(self, key: _KT) -> None: ...
    @overload
    def pop(self, key: _KT, compartment: _T) -> None: ...
    @overload
    def pop(self, key: _KT, compartment: _T, compartment2: _T2) -> None: ...
    @overload
    def resolve_single_match(self, var: str, l: list[VariableValue]) -> None: ...
    @overload
    def resolve_single_match(self, var: str, compartment: _T, l: list[VariableValue]) -> None: ...
    @overload
    def resolve_single_match(self, var: str, compartment: _T, compartment2: _T2, l: list[VariableValue]) -> None: ...
    def __getitem__(self, key: _KT) -> _VT | None: ...
    def __setitem__(self, key: _KT, value: _VT) -> None: ...
    def __delitem__(self, key: _KT) -> None: ...
    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...
    
class Collections(
    Generic[_T_CollectionKey, _T_CollectionCls]
):
    global_collection: tuple[str, Collection[str]]
    ip_collection: tuple[str, Collection[str]]
    session_collection: tuple[str, Collection[str]]
    user_collection: tuple[str, Collection[str]]
    resource_collection: tuple[str, Collection[str]]
    def __iter__(self: Collections) -> Iterator[tuple[str, _T_CollectionCls]]: ...
    
class RuleMessage:
    transaction_id: str
    data: str
    is_disruptive: bool
    match: str
    message: str
    no_audit_log: bool
    reference: str
    save_message: bool
    severity: int
    tags: list[str]
    
    def reset(self, reset_save_message: bool) -> None: ...
    @overload
    def log(self) -> str: ...
    @overload
    def log(self, props: LogMessageInfo) -> str: ...
    @overload
    def log(self, props: int, response_code: int) -> str: ...
    def error_log(self) -> str: ...
    def _details(self, rule_message: RuleMessage) -> str: ...
    def _error_log_tail(self, rule_message: RuleMessage) -> str: ...
    def get_phase(self) -> int: ...

class UnicodeMap(_Collection[_UT_co], Generic[_UT_co]):
    def __setitem__(self, index: int, value: _UT) -> None: ...
    def __getitem__(self, index: int) -> _UT: ...
    def at(self, index: int) -> _UT: ...
    def change(self, index: int, value: _UT) -> None: ...

class RulesExceptions:
    def add_range(self, range: tuple[int, int]) -> None: ...
    def add_number(self, value: int) -> None: ...
    def __contains__(self, other: int) -> bool: ...
    
class RulesSetProperties:
    class RuleEngine(IntEnum):
        DisabledRuleEngine: int
        EnabledRuleEngine: int
        DetectionOnlyRuleEngine: int
        PropertyNotSetRuleEngine: int

    class BodyLimitAction(IntEnum):
        ProcessPartialBodyLimitAction: int
        RejectBodyLimitAction: int
        PropertyNotSetBodyLimitAction: int

    class OnFailedRemoteRulesAction(IntEnum):
        AbortOnFailedRemoteRulesAction: int
        WarnOnFailedRemoteRulesAction: int
        PropertyNotSetRemoteRulesAction: int

    audit_log: AuditLog
    request_body_limit_action: RulesSetProperties.BodyLimitAction
    response_body_limit_action: RulesSetProperties.BodyLimitAction
    sec_request_body_access: bool
    sec_response_body_access: bool
    sec_xml_external_entity: bool
    tmp_save_uploaded_files: bool
    upload_keep_files: bool
    arguments_limit: float
    request_body_json_depth_limit: float
    request_body_limit: int
    request_body_no_files_limit: float
    response_body_limit: float
    pcre_match_limit: int
    upload_file_limit: int
    upload_file_mode: int
    debug_log: DebugLog
    remote_rules_action_on_failed: RulesSetProperties.OnFailedRemoteRulesAction
    sec_rule_engine: RulesSetProperties.RuleEngine
    exceptions: RulesExceptions
    components: list[str]
    response_body_type_to_be_inspected: set[str]
    httpbl_key: str
    upload_directory: str
    upload_tmp_directory: str
    sec_argument_separator: str
    sec_web_app_id: str
    unicode_map_table: UnicodeMap
    
class RulesSet(RulesSetProperties):
    def __init__(self) -> None: ...
    def load_from_uri(self, file: StrOrBytesPath) -> None: ...
    def merge(self, source: RulesSet) -> None: ...
    def dump(self) -> None: ...
    def load_from_remote(self, key: str, uri: str) -> None: ...
    def load_from_plaintext(self, plaintext: str, /) -> None: ...
    
class ModSecurity:
    global_collection: Collection[str]
    resource_collection: Collection[str]
    ip_collection: Collection[str]
    session_collection: Collection[str]
    user_collection: Collection[str]
    
    def __init__(self) -> None: ...
    @overload
    def set_log_cb(self, log_cb: LogCbFunc) -> None: ...
    @overload
    def set_log_cb(self, log_cb: LogCbFunc, properties: int = LogProperty.TextLogProperty) -> None: ...
    def set_connector_info(self, connector: str) -> None: ...
    def get_connector_info(self) -> str: ...
    def who_am_i(self) -> str: ...

class DebugLog:
    def is_log_file_set(self) -> bool: ...
    def is_log_level_set(self) -> bool: ...
    def set_debug_log_level(self, level: int) -> None: ...
    def set_debug_log_file(self, file: StrOrBytesPath) -> None: ...
    def get_debug_log_file(self) -> str: ...
    def get_debug_log_level(self) -> int: ...
    
class AuditLogType(IntEnum):
    NotSetAuditLogType: int
    SerialAuditLogType: int
    ParallelAuditLogType: int
    HttpsAuditLogType: int

class AuditLogStatus(IntEnum):
    NotSetLogStatus: int
    OnAuditLogStatus: int
    OffAuditLogStatus: int
    RelevantOnlyAuditLogStatus: int

class AuditLogFormat(IntEnum):
    NotSetAuditLogFormat: int
    JSONAuditLogFormat: int
    NativeAuditLogFormat: int

class AuditLogParts(IntEnum):
    AAuditLogPart: int
    BAuditLogPart: int
    CAuditLogPart: int
    DAuditLogPart: int
    EAuditLogPart: int
    FAuditLogPart: int
    GAuditLogPart: int
    HAuditLogPart: int
    IAuditLogPart: int
    JAuditLogPart: int
    KAuditLogPart: int
    ZAuditLogPart: int
        
class AuditLog:

    @property
    def m_path1(self) -> str: ...
    @property
    def m_path2(self) -> str: ...
    @property
    def m_storage_dir(self) -> str: ...
    @property
    def m_format(self) -> AuditLogFormat: ...

    def set_storage_dir_mode(self, permission: int) -> None: ...
    def set_file_mode(self, permission: int) -> None: ...
    def set_status(self, new_status: AuditLogStatus = AuditLogStatus.OnAuditLogStatus) -> None: ...
    def set_relevant_status(self, new_relevant_status: str) -> None: ...
    def set_file_path1(self, path: StrOrBytesPath) -> None: ...
    def set_file_path2(self, path: StrOrBytesPath) -> None: ...
    def set_storage_dir(self, path: StrOrBytesPath) -> None: ...
    def set_format(self, fmt: AuditLogFormat = AuditLogFormat.JSONAuditLogFormat) -> None: ...

    def get_directory_permission(self) -> int: ...
    def get_file_permission(self) -> int: ...
    def get_parts(self) -> int: ...

    def set_parts(self, new_parts: str) -> None: ...
    def set_type(self, audit_type: AuditLogType) -> None: ...

    def save_if_relevant(self, transaction: Transaction, parts: int = -1) -> None: ...
    def is_relevant(self, status: int) -> bool: ...
    @staticmethod
    def add_parts(parts: int, new_parts: str) -> int: ...
    @staticmethod
    def remove_parts(parts: int, new_parts: str) -> int: ...
    def set_ctl_audit_engine_active(self) -> None: ...
    
class Intervention:
    @property
    def status(self) -> int: ...
    @property
    def pause(self) -> int: ...
    @property
    def url(self) -> str: ...
    @property
    def log(self) -> str: ...
    @property
    def disruptive(self) -> int: ...

class AnchoredSetVariable(Generic[_KT, _VT]):
    name: _T
    @overload
    def set(self, key: _KT, value: _VT, offset: int) -> None: ...
    @overload
    def set(self, key: _KT, value: _VT, offset: int, len: int) -> None: ...
    def resolve(self, variable_values: Sequence[VariableValue]) -> None: ...
    def resolve_first(self, key: _KT) -> _VT: ...
    
class AnchoredVariable(Generic[_KT, _VT]):
    name: _T
    @overload
    def set(self, key: _KT, offset: int) -> None: ...
    @overload
    def set(self, key: _KT, offset: int, offset_len: int) -> None: ...
    def resolve_first(self) -> _VT: ...
    
class AnchoredSetVariableTranslationProxy:
    name: _T
    @overload
    def resolve(self, variable_values: Sequence[VariableValue]) -> None: ...
    @overload
    def resolve(self, key: _KT, variable_values: Sequence[VariableValue]) -> None: ...
    def resolve_first(self, key: _KT, variable_values: Sequence[VariableValue]) -> _VT: ...
        
class TransactionAnchoredVariables:
    variableRequestHeadersNames: AnchoredSetVariable
    variableResponseContentType: AnchoredVariable
    variableResponseHeadersNames: AnchoredSetVariable
    variableARGScombinedSize: AnchoredVariable
    variableAuthType: AnchoredVariable
    variableFilesCombinedSize: AnchoredVariable
    variableFullRequest: AnchoredVariable
    variableFullRequestLength: AnchoredVariable
    variableInboundDataError: AnchoredVariable
    variableMatchedVar: AnchoredVariable
    variableMatchedVarName: AnchoredVariable
    variableMscPcreError: AnchoredVariable
    variableMscPcreLimitsExceeded: AnchoredVariable
    variableMultipartBoundaryQuoted: AnchoredVariable
    variableMultipartBoundaryWhiteSpace: AnchoredVariable
    variableMultipartCrlfLFLines: AnchoredVariable
    variableMultipartDataAfter: AnchoredVariable
    variableMultipartDataBefore: AnchoredVariable
    variableMultipartFileLimitExceeded: AnchoredVariable
    variableMultipartHeaderFolding: AnchoredVariable
    variableMultipartInvalidHeaderFolding: AnchoredVariable
    variableMultipartInvalidPart: AnchoredVariable
    variableMultipartInvalidQuoting: AnchoredVariable
    variableMultipartLFLine: AnchoredVariable
    variableMultipartMissingSemicolon: AnchoredVariable
    variableMultipartStrictError: AnchoredVariable
    variableMultipartUnmatchedBoundary: AnchoredVariable
    variableOutboundDataError: AnchoredVariable
    variablePathInfo: AnchoredVariable
    variableQueryString: AnchoredVariable
    variableRemoteAddr: AnchoredVariable
    variableRemoteHost: AnchoredVariable
    variableRemotePort: AnchoredVariable
    variableReqbodyError: AnchoredVariable
    variableReqbodyErrorMsg: AnchoredVariable
    variableReqbodyProcessorError: AnchoredVariable
    variableReqbodyProcessorErrorMsg: AnchoredVariable
    variableReqbodyProcessor: AnchoredVariable
    variableRequestBasename: AnchoredVariable
    variableRequestBody: AnchoredVariable
    variableRequestBodyLength: AnchoredVariable
    variableRequestFilename: AnchoredVariable
    variableRequestLine: AnchoredVariable
    variableRequestMethod: AnchoredVariable
    variableRequestProtocol: AnchoredVariable
    variableRequestURI: AnchoredVariable
    variableRequestURIRaw: AnchoredVariable
    variableResource: AnchoredVariable
    variableResponseBody: AnchoredVariable
    variableResponseContentLength: AnchoredVariable
    variableResponseProtocol: AnchoredVariable
    variableResponseStatus: AnchoredVariable
    variableServerAddr: AnchoredVariable
    variableServerName: AnchoredVariable
    variableServerPort: AnchoredVariable
    variableSessionID: AnchoredVariable
    variableUniqueID: AnchoredVariable
    variableUrlEncodedError: AnchoredVariable
    variableUserID: AnchoredVariable
    
    variableArgs: AnchoredSetVariable
    variableArgsGet: AnchoredSetVariable
    variableArgsPost: AnchoredSetVariable
    variableFilesSizes: AnchoredSetVariable
    variableFilesNames: AnchoredSetVariable
    variableFilesTmpContent: AnchoredSetVariable
    variableMultipartFileName: AnchoredSetVariable
    variableMultipartName: AnchoredSetVariable
    variableMatchedVarsNames: AnchoredSetVariable
    variableMatchedVars: AnchoredSetVariable
    variableFiles: AnchoredSetVariable
    variableRequestCookies: AnchoredSetVariable
    variableRequestHeaders: AnchoredSetVariable
    variableResponseHeaders: AnchoredSetVariable
    variableGeo: AnchoredSetVariable
    variableRequestCookiesNames: AnchoredSetVariable
    variableFilesTmpNames: AnchoredSetVariable
    variableMultipartPartHeaders: AnchoredSetVariable
        
    variableArgsNames: AnchoredSetVariableTranslationProxy
    variableArgsGetNames: AnchoredSetVariableTranslationProxy
    variableArgsPostNames: AnchoredSetVariableTranslationProxy
    
class Transaction(TransactionAnchoredVariables):
    id: str | None
    msc: ModSecurity
    uri: str
    request_body_type: RequestBodyType
    request_body_processor: RequestBodyType
    rules_set: RulesSet
    collections: Collections
    rule_messages: list[RuleMessage]
    actions: list[Intervention]
    @overload
    def __init__(self, msc: ModSecurity, rules_set: RulesSet, id: str) -> None: ...
    @overload
    def __init__(self, msc: ModSecurity, rules_set: RulesSet) -> None: ...
    
    def to_old_audit_log_format(self, parts: int, trailer: str) -> str: ...
    def to_dict(self, parts: int) -> dict[str, Any]: ...
    def process_connection(self, remote_addr: str, remote_port: int, server_addr: str, server_port: int) -> None: ...
    def process_uri(self, uri: str, method: str, version: str) -> None: ...
    def process_request_headers(self) -> None: ...
    def add_request_header(self, key: _KT, value: _VT) -> None: ...
    def process_request_body(self) -> None: ...
    def process_response_headers(self, status: int, protocol: str) -> None: ...
    def process_logging(self) -> None: ...
    def append_request_body(self, body: ReadableBuffer) -> None: ...
    def append_request_body_from_file(self, file: StrOrBytesPath) -> None: ...
    def add_response_header(self, key: _KT, value: _VT) -> None: ...
    def process_response_body(self) -> None: ...
    def append_response_body(self, body: ReadableBuffer) -> None: ...
    def intervention(self) -> Intervention | None: ...
    def get_response_body(self) -> bytes: ...
    def get_response_body_length(self) -> int: ...
    def get_request_body_length(self) -> int: ...
    def update_status_code(self, status: int) -> None: ...
    def set_request_hostname(self, hostname: str) -> None: ...
    def get_rule_engine_state(self) -> int: ...
    
def init() -> ModSecurity: ...