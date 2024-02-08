//https://www.elastic.co/guide/en/ecs/current/index.html
// Some of this events are automatically created when you map a SiemLog to a SiemEvent. The object field types are not supported for simplicity in uSIEM.
// If needed join the values by the character "\n" into a single String. Useful for file names.
pub const EVENT_OUTCOME: &str = "event.outcome";
/// The action captured by the event. This describes the information in the event. It is more specific than event.category. Examples are group-add, process-started, file-created. The value is normally defined by the implementer.
pub const EVENT_ACTION: &str = "event.action";
/// event.category represents the "big buckets" of ECS categories. For example, filtering on event.category:process yields all events relating to process activity. Valudes: authentication, configuration, database, driver, file, host, iam, intrusion_detection, malware, network, package, process, web
pub const EVENT_CATEGORY: &str = "event.category";
/// Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID.
pub const EVENT_CODE: &str = "event.code";

pub const USER_NAME: &str = "user.name";
pub const USER_DOMAIN: &str = "user.domain";
pub const SOURCE_IP: &str = "source.ip";
pub const SOURCE_PORT: &str = "source.port";
/// Amount of bytes sent by the local host
pub const SOURCE_BYTES: &str = "source.bytes";
pub const DESTINATION_IP: &str = "destination.ip";
pub const DESTINATION_PORT: &str = "destination.port";

/// Amount of bytes sent by the remote host
pub const DESTINATION_BYTES: &str = "destination.bytes";

pub const NETWORK_TRANSPORT: &str = "network.transport";
pub const NETWORK_PROTOCOL: &str = "network.protocol";
pub const NETWORK_DURATION: &str = "network.duration";

pub const IN_INTERFACE: &str = "observer.ingress.interface";
pub const OUT_INTERFACE: &str = "observer.egress.interface";

pub const OBSERVER_IP: &str = "observer.ip";
pub const OBSERVER_NAME: &str = "observer.name";

pub const URL_FULL: &str = "url.full";
pub const URL_DOMAIN: &str = "url.domain";
pub const URL_PATH: &str = "url.path";
pub const URL_QUERY: &str = "url.query";

pub const HTTP_REQUEST_METHOD: &str = "http.request.method";
pub const HTTP_RESPONSE_MIME_TYPE: &str = "http.response.mime_type";
pub const HTTP_RESPONSE_STATUS_CODE: &str = "http.response.status_code";

pub const RULE_NAME: &str = "rule.name";
pub const RULE_CATEGORY: &str = "rule.category";
pub const RULE_ID: &str = "rule.id";

pub const DNS_OP_CODE: &str = "dns.op_code";
pub const DNS_ANSWER_CLASS: &str = "dns.answer.class";
pub const DNS_ANSWER_NAME: &str = "dns.answer.name";
pub const DNS_ANSWER_TYPE: &str = "dns.answer.type";
pub const DNS_ANSWER_TTL: &str = "dns.answer.ttl";
pub const DNS_ANSWER_DATA: &str = "dns.answer.data";
pub const DNS_QUESTION_CLASS: &str = "dns.question.class";
pub const DNS_QUESTION_NAME: &str = "dns.question.name";
pub const DNS_QUESTION_TYPE: &str = "dns.question.type";
pub const DNS_RESOLVED_IP: &str = "dns.resolved_ip";

pub const DHCP_RECORD_TYPE: &str = "dhcp.type";

pub const TAG_REPROCESS: &str = "reprocess_log";

pub const ARTIFACT_NAME: &str = "artifact.name";
pub const ARTIFACT_PATH: &str = "artifact.path";
pub const ARTIFACT_HOST: &str = "artifact.host";
pub const ARTIFACT_TENANT: &str = "artifact.tenant";

pub const PROCESS_EXECUTABLE : &str = "process.executable";

pub const FILE_INODE : &str = "file.inode";
pub const FILE_NAME : &str = "file.name";
pub const FILE_OWNER : &str = "file.OWNER";
pub const FILE_PATH : &str = "file.path";
pub const FILE_SIZE : &str = "file.size";
pub const FILE_TYPE : &str = "file.type";
pub const FILE_ACCESSED : &str = "file.accessed";
pub const FILE_CREATED : &str = "file.created";
pub const FILE_DEVICE : &str = "file.device";
pub const FILE_DIRECTORY : &str = "file.directory";
pub const FILE_EXTENSION : &str = "file.extension";


pub const PE_IMPORTS : &str = "pe.imports";