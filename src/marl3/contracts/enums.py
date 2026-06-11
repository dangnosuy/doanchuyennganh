from enum import Enum


class Role(str, Enum):
    CRAWLER = "crawler"
    HUNTER = "hunter"
    RED = "red"
    BLUE = "blue"
    EXEC = "exec"
    VERIFIER = "verifier"
    REPORTER = "reporter"


class BugCategory(str, Enum):
    BAC = "BAC"
    BLF = "BLF"


class BugState(str, Enum):
    QUEUED = "QUEUED"
    DEBATING = "DEBATING"
    DEBATE_APPROVED = "DEBATE_APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    EXPLOITED = "EXPLOITED"
    INFO_EXPOSURE_ONLY = "INFO_EXPOSURE_ONLY"
    NOT_EXPLOITED = "NOT_EXPLOITED"
    PROOF_QUALITY_FAIL = "PROOF_QUALITY_FAIL"
    SKIPPED = "SKIPPED"
    SKIPPED_NO_EVIDENCE = "SKIPPED_NO_EVIDENCE"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerdictStatus(str, Enum):
    EXPLOITED = "EXPLOITED"
    INFO_EXPOSURE_ONLY = "INFO_EXPOSURE_ONLY"
    PROOF_QUALITY_FAIL = "PROOF_QUALITY_FAIL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class DebateVerdict(str, Enum):
    APPROVE = "APPROVE"
    REVISE = "REVISE"
    STOP = "STOP"
    UNVERIFIABLE = "UNVERIFIABLE"  # context too thin for Blue to evaluate — Red must refuse/warn


class ProofKey(str, Enum):
    OWNERSHIP_BYPASS = "OWNERSHIP_BYPASS"
    PRIVILEGED_ACCESS = "PRIVILEGED_ACCESS"
    STATE_DELTA = "STATE_DELTA"
    AUTH_BYPASS = "AUTH_BYPASS"
    PRICE_MANIPULATION = "PRICE_MANIPULATION"
    QUANTITY_TAMPER = "QUANTITY_TAMPER"
    STATE_SKIP = "STATE_SKIP"
    SENSITIVE_FIELD_EXPOSED = "SENSITIVE_FIELD_EXPOSED"
