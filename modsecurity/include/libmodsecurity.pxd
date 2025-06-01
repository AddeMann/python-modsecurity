# distutils: language = c++

from libcpp cimport bool
from libcpp.string cimport string
from libcpp.list cimport list
from libcpp.memory cimport shared_ptr
from libcpp.set cimport set
from libcpp.vector cimport vector
from libc.stdint cimport int64_t
from libc.stdint cimport int32_t
from libcpp.pair cimport pair
from libcpp.memory cimport unique_ptr

cdef extern from "modsecurity/rule.h" namespace "modsecurity":
    cdef cppclass Rule:
        Rule(const string &fileName, int lineNumber) except +
        const string& getFileName() const
        int getLineNumber() const
        int getPhase() const
        void setPhase(int phase)
        string getReference()
        bint isMarker()

cdef extern from "modsecurity/rules.h" namespace "modsecurity":
    cdef cppclass Rules:
        Rules() except +
        void dump() const

        int append(Rules *_from, const vector[int64_t] &ids, string *err)

        bint insert(const shared_ptr[Rule] &rule)
        bint insert(shared_ptr[Rule] rule, const vector[int64_t] *ids, string *err)

        size_t size() const
        shared_ptr[Rule] operator[](int index) const
        shared_ptr[Rule] at(int index) const

        vector[shared_ptr[Rule]] m_rules
        
cdef extern from "modsecurity/rule_message.h" namespace "modsecurity":
    cdef cppclass RuleMessage:
        enum LogMessageInfo:
           ErrorLogTailLogMessageInfo = 2,
           ClientLogMessageInfo = 4

        RuleMessage(Rule *rule, Transaction *transaction) except +  # constructor
        void reset(const bint resetSaveMessage)
        string log() const
        string log(int props) const
        string log(int props, int responseCode) const
        string errorLog() const
        string _details(const RuleMessage &rm)
        string _errorLogTail(const RuleMessage &rm)
        int getPhase() const

        const Rule m_rule
        const Transaction m_transaction
        string m_data
        bint m_isDisruptive
        string m_match
        string m_message
        bint m_noAuditLog
        string m_reference
        bint m_saveMessage
        int m_severity

        list[string] m_tags
        
cdef extern from "modsecurity/debug_log.h" namespace "modsecurity::debug_log":
    cdef cppclass DebugLog:
        DebugLog()

        bool isLogFileSet();
        bool isLogLevelSet();
        void setDebugLogLevel(int level);
        void setDebugLogFile(const string &fileName, string *error);
        const string& getDebugLogFile()
        int getDebugLogLevel()

        int m_debugLevel;

cdef extern from "modsecurity/rules_set_properties.h" namespace "modsecurity::Parser":
    cdef cppclass Driver:
        pass

cdef extern from "modsecurity/rules_set_phases.h" namespace "modsecurity":
    cdef cppclass RulesSetPhases:

        bool insert(shared_ptr[Rule] rule)

        int append(RulesSetPhases *_from, string *err)
        void dump() const;

        Rules *operator[](int index)
        Rules *at(int index)

cdef extern from "modsecurity/audit_log.h" namespace "modsecurity::audit_log":
    cdef cppclass AuditLog:
        AuditLog()

        ctypedef enum AuditLogType:
            NotSetAuditLogType,
            SerialAuditLogType,
            ParallelAuditLogType,
            HttpsAuditLogType

        ctypedef enum AuditLogStatus:
            NotSetLogStatus,
            OnAuditLogStatus,
            OffAuditLogStatus,
            RelevantOnlyAuditLogStatus

        ctypedef enum AuditLogFormat:
            NotSetAuditLogFormat,
            JSONAuditLogFormat,
            NativeAuditLogFormat

        ctypedef enum AuditLogParts:
            AAuditLogPart = 2,
            BAuditLogPart = 4,
            CAuditLogPart = 8,
            DAuditLogPart = 16,
            EAuditLogPart = 32,
            FAuditLogPart = 64,
            GAuditLogPart = 128,
            HAuditLogPart = 256,
            IAuditLogPart = 512,
            JAuditLogPart = 1024,
            KAuditLogPart = 2048,
            ZAuditLogPart = 4096

        bint setStorageDirMode(int permission)
        bint setFileMode(int permission)
        bint setStatus(AuditLogStatus new_status)
        bint setRelevantStatus(const string& new_relevant_status)
        bint setFilePath1(const string& path)
        bint setFilePath2(const string& path)
        bint setStorageDir(const string& path)
        bint setFormat(AuditLogFormat fmt)

        int getDirectoryPermission() const
        int getFilePermission() const
        int getParts() const

        bint setParts(const string& new_parts)
        bint setType(AuditLogType audit_type)

        bint init(string *error)
        bint close()

        bint saveIfRelevant(Transaction *transaction)
        bint saveIfRelevant(Transaction *transaction, int parts)
        bint isRelevant(int status)
        @staticmethod
        int addParts(int parts, const string& new_parts)
        @staticmethod
        int removeParts(int parts, const string& new_parts)

        void setCtlAuditEngineActive()

        bint merge(AuditLog *_from, string *error)

        string m_path1
        string m_path2
        string m_storage_dir

        AuditLogFormat m_format

cdef extern from "modsecurity/rules_exceptions.h" namespace "modsecurity":
    cdef cppclass RulesExceptions:
        RulesExceptions() except +

        bool load(const string &data, string *error)
        bool addRange(int a, int b)
        bool addNumber(int a)
        bool contains(int a)
        bool merge(RulesExceptions *_from)

        bool loadRemoveRuleByMsg(const string &msg, string *error)
        bool loadRemoveRuleByTag(const string &msg, string *error)
        
cdef extern from "modsecurity/variable_origin.h" namespace "modsecurity":
    cdef cppclass VariableOrigin:
        VariableOrigin()  # Standardkonstruktor
        VariableOrigin(size_t length, size_t offset)  # Konstruktor med längd och offset
        string toText() const  # Returnerar en strängrepresentation

        size_t m_length
        size_t m_offset

cdef extern from "modsecurity/variable_value.h" namespace "modsecurity":  # Ändra om namespace skiljer sig

    cdef cppclass VariableValue:
        ctypedef vector[VariableOrigin] Origins

        # Konstruktorer
        VariableValue(const string* key, const string* value)
        VariableValue(const string* collection, const string* key, const string* value)
        VariableValue(const VariableValue* o)
        VariableValue(const VariableValue&)

        # Metoder
        const string& getKey() const
        const string& getKeyWithCollection() const
        const string& getCollection() const
        const string& getValue() const
        void setValue(const string& value)
        void addOrigin(const VariableOrigin& origin)
        const Origins& getOrigin() const
        void reserveOrigin(size_t additionalSize)

        # Medlemmar
        Origins m_orign
        string m_collection
        string m_key
        string m_keyWithCollection
        string m_value

cdef extern from "modsecurity/rules_set_properties.h" namespace "modsecurity":
    cdef cppclass ConfigInt:
        ConfigInt()
        bool m_set
        int m_value
        void merge(const ConfigInt *_from)


    cdef cppclass ConfigDouble:
        ConfigDouble()
        bool m_set
        double m_value

        void merge(const ConfigDouble *_from)


    cdef cppclass ConfigString:
        ConfigString()
        bool m_set
        string m_value

        void merge(const ConfigString *_from)


    cdef cppclass ConfigSet:
        ConfigSet()
        bool m_set
        bool m_clear
        set[string] m_value


    cdef cppclass UnicodeMapHolder:
        UnicodeMapHolder()
        int& operator[](int index)
        int operator[](int index) const
        int at(int index) const
        void change(int i, int a)
        int[65536] m_data

    cdef cppclass ConfigUnicodeMap:
        ConfigUnicodeMap()

        void loadConfig(string f, double codePage, RulesSetProperties *driver, string *errg)

        void merge(const ConfigUnicodeMap *_from)

        bool m_set
        double m_unicodeCodePage
        shared_ptr[UnicodeMapHolder] m_unicodeMapTable

    cdef cppclass RulesSetProperties:
        RulesSetProperties() except +  # constructor
        RulesSetProperties(DebugLog *debugLog)

        enum ConfigBoolean:
            TrueConfigBoolean = 0
            FalseConfigBoolean = 1
            PropertyNotSetConfigBoolean = 2

        enum RuleEngine:
            DisabledRuleEngine,
            EnabledRuleEngine,
            DetectionOnlyRuleEngine,
            PropertyNotSetRuleEngine

        enum BodyLimitAction:
            ProcessPartialBodyLimitAction,
            RejectBodyLimitAction,
            PropertyNotSetBodyLimitAction

        enum OnFailedRemoteRulesAction:
            AbortOnFailedRemoteRulesAction,
            WarnOnFailedRemoteRulesAction,
            PropertyNotSetRemoteRulesAction

        const char *ruleEngineStateString(RuleEngine i)
        string configBooleanString(ConfigBoolean i)
        int mergeProperties(RulesSetProperties *_from, RulesSetProperties *to, string *err)

        AuditLog *m_auditLog
        BodyLimitAction m_requestBodyLimitAction
        BodyLimitAction m_responseBodyLimitAction
        ConfigBoolean m_secRequestBodyAccess
        ConfigBoolean m_secResponseBodyAccess
        ConfigBoolean m_secXMLExternalEntity
        ConfigBoolean m_tmpSaveUploadedFiles
        ConfigBoolean m_uploadKeepFiles
        ConfigDouble m_argumentsLimit
        ConfigDouble m_requestBodyJsonDepthLimit
        ConfigDouble m_requestBodyLimit
        ConfigDouble m_requestBodyNoFilesLimit
        ConfigDouble m_responseBodyLimit
        ConfigInt m_pcreMatchLimit
        ConfigInt m_uploadFileLimit
        ConfigInt m_uploadFileMode
        DebugLog *m_debugLog
        OnFailedRemoteRulesAction m_remoteRulesActionOnFailed
        RuleEngine m_secRuleEngine
        RulesExceptions m_exceptions
        list[string] m_components
        ConfigSet m_responseBodyTypeToBeInspected
        ConfigString m_httpblKey
        ConfigString m_uploadDirectory
        ConfigString m_uploadTmpDirectory
        ConfigString m_secArgumentSeparator
        ConfigString m_secWebAppId
        ConfigUnicodeMap m_unicodeMapTable

cdef extern from "modsecurity/rules_set.h" namespace "modsecurity":
    cdef cppclass RulesSet(RulesSetProperties):
        RulesSet() except +
        RulesSet(DebugLog *customLog) except +

        int loadFromUri(const char *uri)
        int loadRemote(const char *key, const char *uri)
        int load(const char *rules)
        int load(const char *rules, const string &ref)
        void dump() const
        int merge(RulesSet *rules)
        int merge(Driver *driver)

        string getParserError()

        void debug(int level, const string &id, const string &uri, const string &msg)
        RulesSetPhases m_rulesSetPhases

cdef extern from "<modsecurity/collection/collection.h>" namespace "modsecurity::variables":
    cdef cppclass KeyExclusions:
        pass
cdef extern from "<modsecurity/collection/collection.h>" namespace "modsecurity::collection":
    cdef cppclass Collection:
        Collection(const string &a) except +

        bint storeOrUpdateFirst(const string &key, const string &value)
        bint storeOrUpdateFirst(const string &key, string compartment, const string &value)
        bint storeOrUpdateFirst(const string &key, string compartment, string compartment2, const string &value)
        void resolveSingleMatch(const string& var, vector[const VariableValue *] *l)
        void resolveSingleMatch(const string& var, string compartment, vector[const VariableValue *] *l)
        void resolveSingleMatch(const string& var, string compartment, string compartment2, vector[const VariableValue *] *l)
        void resolveMultiMatches(const string& var, vector[const VariableValue *] *l, KeyExclusions &ke)
        void resolveMultiMatches(const string& var, string compartment, vector[const VariableValue *] *l, KeyExclusions &ke)
        void resolveMultiMatches(const string& var, string compartment, string compartment2, vector[const VariableValue *] *l, KeyExclusions &ke)
        bint updateFirst(const string &key, const string &value)
        bint updateFirst(const string &key, string compartment, const string &value)
        bint updateFirst(const string &key, string compartment, string compartment2, const string &value)
        void _del "del" (const string &key)
        void _del "del" (const string& key, string compartment)
        void _del "del" (const string& key, string compartment, string compartment2)
        unique_ptr[string] resolveFirst(string& var)
        unique_ptr[string] resolveFirst(const string& var, string compartment)
        unique_ptr[string] resolveFirst(const string& var, string compartment, string compartment2)
        void setExpiry(const string& key, int32_t expiry_seconds)
        void setExpiry(const string& key, string compartment, int32_t expiry_seconds)
        void setExpiry(const string& key, string compartment, string compartment2, int32_t expiry_seconds)
        void resolveRegularExpression(const string& var, vector[const VariableValue *] *l, KeyExclusions &ke)
        void resolveRegularExpression(const string& var, string compartment, vector[const VariableValue *] *l, KeyExclusions &ke)
        void resolveRegularExpression(const string& var, string compartment, string compartment2, vector[const VariableValue *] *l, KeyExclusions &ke)
        string m_name

cdef extern from "<modsecurity/collection/collections.h>" namespace "modsecurity::collection":
    cdef cppclass Collections:
        Collections(Collection *_global, Collection *ip, Collection *session, Collection *user, Collection *resource) except +
        string m_global_collection_key
        string m_ip_collection_key
        string m_session_collection_key
        string m_user_collection_key
        string m_resource_collection_key

        Collection *m_global_collection
        Collection *m_ip_collection
        Collection *m_session_collection
        Collection *m_user_collection
        Collection *m_resource_collection
        Collection *m_tx_collection

cdef extern from "modsecurity/intervention.h" namespace "modsecurity":
    ctypedef struct ModSecurityIntervention_t:
        int status
        int pause
        char *url
        char *log
        int disruptive

    ctypedef ModSecurityIntervention_t ModSecurityIntervention

cdef extern from "modsecurity/intervention.h" namespace "modsecurity::intervention":
    void free(ModSecurityIntervention_t *i)

cdef extern from "modsecurity/modsecurity.h":
    const char *MODSECURITY_VERSION
    ctypedef void (*ModSecLogCb) (void *, const void *)
    
cdef extern from "modsecurity/modsecurity.h" namespace "modsecurity":

    enum Phases:
        ConnectionPhase
        UriPhase
        RequestHeadersPhase
        RequestBodyPhase
        ResponseHeadersPhase
        ResponseBodyPhase
        LoggingPhase
        NUMBER_OF_PHASES

    cdef enum LogProperty:
        TextLogProperty = 1,
        RuleMessageLogProperty = 2,
        IncludeFullHighlightLogProperty = 4,

    cdef cppclass ModSecurity:
        ModSecurity() except +  # constructor

        const string& whoAmI()
        void setConnectorInformation(const string &connector)
        void setServerLogCb(ModSecLogCb cb)
        void setServerLogCb(ModSecLogCb cb, int properties)
        const string& getConnectorInformation() const
        int processContentOffset(const char *content, size_t len, const char *matchString, string *json, const char **err)
        Collection *m_global_collection
        Collection *m_resource_collection
        Collection *m_ip_collection
        Collection *m_session_collection
        Collection *m_user_collection
        
cdef extern from "modsecurity/anchored_set_variable.h" namespace "modsecurity":

    cdef cppclass AnchoredSetVariable(VariableValue):
        AnchoredSetVariable(Transaction *t, const string &name)
        void unset()
        void set(const string &key, const string &value, size_t offset)
        void set(const string &key, const string &value, size_t offset, size_t len)
        void setCopy(string key, string value, size_t offset)
        void resolve(vector[const VariableValue *] *l)
        void resolve(const string &key, vector[const VariableValue *] *l)

        unique_ptr[string] resolveFirst(const string &key)

        Transaction *m_transaction
        string m_name

cdef extern from "modsecurity/anchored_set_variable_translation_proxy.h" namespace "modsecurity":
    cdef cppclass AnchoredSetVariableTranslationProxy:
        AnchoredSetVariableTranslationProxy(const string &name, AnchoredSetVariable* fount)
        void resolve(vector[const VariableValue*] *l)
        void resolve(const string &key, vector[const VariableValue*] *l)
        unique_ptr[string] resolveFirst(const string &key)
        string m_name
cdef extern from "modsecurity/anchored_variable.h" namespace "modsecurity":
    cdef cppclass AnchoredVariable:
        AnchoredVariable(Transaction* t, const string &name)

        void unset();
        void set(const string &a, size_t offset)
        void set(const string &a, size_t offset, size_t offsetLen)

        void evaluate(vector[const VariableValue *] *l)
        string*  evaluate()
        unique_ptr[string] resolveFirst()

        Transaction *m_transaction
        int m_offset
        string m_name
        string m_value
cdef extern from "modsecurity/transaction.h" namespace "modsecurity":
    cdef cppclass TransactionAnchoredVariables:
        TransactionAnchoredVariables(Transaction *t)

        AnchoredSetVariable m_variableRequestHeadersNames;
        AnchoredVariable m_variableResponseContentType;
        AnchoredSetVariable m_variableResponseHeadersNames;
        AnchoredVariable m_variableARGScombinedSize;
        AnchoredVariable m_variableAuthType;
        AnchoredVariable m_variableFilesCombinedSize;
        AnchoredVariable m_variableFullRequest;
        AnchoredVariable m_variableFullRequestLength;
        AnchoredVariable m_variableInboundDataError;
        AnchoredVariable m_variableMatchedVar;
        AnchoredVariable m_variableMatchedVarName;
        AnchoredVariable m_variableMscPcreError;
        AnchoredVariable m_variableMscPcreLimitsExceeded;
        AnchoredVariable m_variableMultipartBoundaryQuoted;
        AnchoredVariable m_variableMultipartBoundaryWhiteSpace;
        AnchoredVariable m_variableMultipartCrlfLFLines;
        AnchoredVariable m_variableMultipartDataAfter;
        AnchoredVariable m_variableMultipartDataBefore;
        AnchoredVariable m_variableMultipartFileLimitExceeded;
        AnchoredVariable m_variableMultipartHeaderFolding;
        AnchoredVariable m_variableMultipartInvalidHeaderFolding;
        AnchoredVariable m_variableMultipartInvalidPart;
        AnchoredVariable m_variableMultipartInvalidQuoting;
        AnchoredVariable m_variableMultipartLFLine;
        AnchoredVariable m_variableMultipartMissingSemicolon;
        AnchoredVariable m_variableMultipartStrictError;
        AnchoredVariable m_variableMultipartUnmatchedBoundary;
        AnchoredVariable m_variableOutboundDataError;
        AnchoredVariable m_variablePathInfo;
        AnchoredVariable m_variableQueryString;
        AnchoredVariable m_variableRemoteAddr;
        AnchoredVariable m_variableRemoteHost;
        AnchoredVariable m_variableRemotePort;
        AnchoredVariable m_variableReqbodyError;
        AnchoredVariable m_variableReqbodyErrorMsg;
        AnchoredVariable m_variableReqbodyProcessorError;
        AnchoredVariable m_variableReqbodyProcessorErrorMsg;
        AnchoredVariable m_variableReqbodyProcessor;
        AnchoredVariable m_variableRequestBasename;
        AnchoredVariable m_variableRequestBody;
        AnchoredVariable m_variableRequestBodyLength;
        AnchoredVariable m_variableRequestFilename;
        AnchoredVariable m_variableRequestLine;
        AnchoredVariable m_variableRequestMethod;
        AnchoredVariable m_variableRequestProtocol;
        AnchoredVariable m_variableRequestURI;
        AnchoredVariable m_variableRequestURIRaw;
        AnchoredVariable m_variableResource;
        AnchoredVariable m_variableResponseBody;
        AnchoredVariable m_variableResponseContentLength;
        AnchoredVariable m_variableResponseProtocol;
        AnchoredVariable m_variableResponseStatus;
        AnchoredVariable m_variableServerAddr;
        AnchoredVariable m_variableServerName;
        AnchoredVariable m_variableServerPort;
        AnchoredVariable m_variableSessionID;
        AnchoredVariable m_variableUniqueID;
        AnchoredVariable m_variableUrlEncodedError;
        AnchoredVariable m_variableUserID;

        AnchoredSetVariable m_variableArgs;
        AnchoredSetVariable m_variableArgsGet;
        AnchoredSetVariable m_variableArgsPost;
        AnchoredSetVariable m_variableFilesSizes;
        AnchoredSetVariable m_variableFilesNames;
        AnchoredSetVariable m_variableFilesTmpContent;
        AnchoredSetVariable m_variableMultipartFileName;
        AnchoredSetVariable m_variableMultipartName;
        AnchoredSetVariable m_variableMatchedVarsNames;
        AnchoredSetVariable m_variableMatchedVars;
        AnchoredSetVariable m_variableFiles;
        AnchoredSetVariable m_variableRequestCookies;
        AnchoredSetVariable m_variableRequestHeaders;
        AnchoredSetVariable m_variableResponseHeaders;
        AnchoredSetVariable m_variableGeo;
        AnchoredSetVariable m_variableRequestCookiesNames;
        AnchoredSetVariable m_variableFilesTmpNames;
        AnchoredSetVariable m_variableMultipartPartHeaders;

        int m_variableOffset;

        AnchoredSetVariableTranslationProxy m_variableArgsNames;
        AnchoredSetVariableTranslationProxy m_variableArgsGetNames;
        AnchoredSetVariableTranslationProxy m_variableArgsPostNames;

    cdef cppclass Transaction(TransactionAnchoredVariables):
        Transaction(ModSecurity *ms, RulesSet *rules, void *logCbData) except +
        Transaction(ModSecurity *ms, RulesSet *rules, const char *id, void *logCbData) except +

        int processConnection(const char *client, int cPort, const char *server, int sPort)
        int processURI(const char *uri, const char *protocol, const char *http_version)
        int processRequestHeaders()
        int addRequestHeader(const string& key, const string& value)
        int processRequestBody()
        int processResponseHeaders(int code, const string& proto)
        int processLogging()

        int appendRequestBody(const unsigned char *body, size_t size);
        int requestBodyFromFile(const char *path);

        int addResponseHeader(const string& key, const string& value)

        int processResponseBody();
        int appendResponseBody(const unsigned char *body, size_t size);

        bint intervention(ModSecurityIntervention *it)

        const char *getResponseBody() const
        size_t getResponseBodyLength()
        size_t getRequestBodyLength()

        int updateStatusCode(int status)

        int setRequestHostName(const string& hostname)
        int getRuleEngineState() const

        string toJSON(int parts)
        string toOldAuditLogFormat(int parts, const string &trailer)

        enum RequestBodyType:
            UnknownFormat,
            MultiPartRequestBody,
            WWWFormUrlEncoded,
            JSONRequestBody,
            XMLRequestBody

        shared_ptr[string] m_id
        shared_ptr[string] m_clientIpAddress
        string m_httpVersion
        shared_ptr[string] m_serverIpAddress
        shared_ptr[string] m_requestHostName

        string m_uri
        shared_ptr[string] m_uri_no_query_string_decoded
        double m_ARGScombinedSizeDouble
        int m_clientPort
        int m_highestSeverityAction
        int m_httpCodeReturned
        int m_serverPort
        ModSecurity *m_ms
        string m_id
        RequestBodyType m_requestBodyType
        RequestBodyType m_requestBodyProcessor
        RulesSet *m_rules
        int m_requestBodyAccess
        void *m_logCbData
        list[int] m_ruleRemoveById
        list[pair[int, int]] m_ruleRemoveByIdRange
        list[RuleMessage] m_rulesMessages
        vector[ModSecurityIntervention] m_actions
        Collections m_collections