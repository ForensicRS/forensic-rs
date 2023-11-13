//https://www.elastic.co/guide/en/ecs/current/index.html
// Some of this events are automatically created when you map a SiemLog to a SiemEvent. The object field types are not supported for simplicity in uSIEM.
// If needed join the values by the character "\n" into a single String. Useful for file names.
pub static EVENT_OUTCOME: &'static str = "event.outcome";
/// The action captured by the event. This describes the information in the event. It is more specific than event.category. Examples are group-add, process-started, file-created. The value is normally defined by the implementer.
pub static EVENT_ACTION: &'static str = "event.action";
/// event.category represents the "big buckets" of ECS categories. For example, filtering on event.category:process yields all events relating to process activity. Valudes: authentication, configuration, database, driver, file, host, iam, intrusion_detection, malware, network, package, process, web
pub static EVENT_CATEGORY: &'static str = "event.category";
/// Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID.
pub static EVENT_CODE: &'static str = "event.code";

pub static USER_NAME: &'static str = "user.name";
pub static USER_DOMAIN: &'static str = "user.domain";
pub static SOURCE_IP: &'static str = "source.ip";
pub static SOURCE_PORT: &'static str = "source.port";
/// Amount of bytes sent by the local host
pub static SOURCE_BYTES: &'static str = "source.bytes";
pub static DESTINATION_IP: &'static str = "destination.ip";
pub static DESTINATION_PORT: &'static str = "destination.port";

/// Amount of bytes sent by the remote host
pub static DESTINATION_BYTES: &'static str = "destination.bytes";

pub static NETWORK_TRANSPORT: &'static str = "network.transport";
pub static NETWORK_PROTOCOL: &'static str = "network.protocol";
pub static NETWORK_DURATION: &'static str = "network.duration";

pub static IN_INTERFACE: &'static str = "observer.ingress.interface";
pub static OUT_INTERFACE: &'static str = "observer.egress.interface";

pub static OBSERVER_IP: &'static str = "observer.ip";
pub static OBSERVER_NAME: &'static str = "observer.name";

pub static URL_FULL: &'static str = "url.full";
pub static URL_DOMAIN: &'static str = "url.domain";
pub static URL_PATH: &'static str = "url.path";
pub static URL_QUERY: &'static str = "url.query";

pub static HTTP_REQUEST_METHOD: &'static str = "http.request.method";
pub static HTTP_RESPONSE_MIME_TYPE: &'static str = "http.response.mime_type";
pub static HTTP_RESPONSE_STATUS_CODE: &'static str = "http.response.status_code";

pub static RULE_NAME: &'static str = "rule.name";
pub static RULE_CATEGORY: &'static str = "rule.category";
pub static RULE_ID: &'static str = "rule.id";

pub static DNS_OP_CODE: &'static str = "dns.op_code";
pub static DNS_ANSWER_CLASS: &'static str = "dns.answer.class";
pub static DNS_ANSWER_NAME: &'static str = "dns.answer.name";
pub static DNS_ANSWER_TYPE: &'static str = "dns.answer.type";
pub static DNS_ANSWER_TTL: &'static str = "dns.answer.ttl";
pub static DNS_ANSWER_DATA: &'static str = "dns.answer.data";
pub static DNS_QUESTION_CLASS: &'static str = "dns.question.class";
pub static DNS_QUESTION_NAME: &'static str = "dns.question.name";
pub static DNS_QUESTION_TYPE: &'static str = "dns.question.type";
pub static DNS_RESOLVED_IP: &'static str = "dns.resolved_ip";

pub static DHCP_RECORD_TYPE: &'static str = "dhcp.type";

pub static TAG_REPROCESS: &'static str = "reprocess_log";

pub static ARTIFACT_NAME: &'static str = "artifact.name";
pub static ARTIFACT_PATH: &'static str = "artifact.path";
pub static ARTIFACT_HOST: &'static str = "artifact.host";
pub static ARTIFACT_TENANT: &'static str = "artifact.tenant";