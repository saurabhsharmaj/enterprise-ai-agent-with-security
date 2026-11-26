"""Guardrails: defence in depth AROUND the model. They are NOT the security boundary (OPA + the executor are);
they reduce abuse, leakage and noise. Modes (GUARDRAIL_MODE): off | monitor (flag + audit, default) | block."""
import re
from dataclasses import dataclass, field

MAX_INPUT_CHARS = 2000

_INJECTION = [
    ("ignore_instructions", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|system)\b.{0,30}\b(instructions?|rules?|prompts?|polic(?:y|ies))\b", re.I | re.S)),
    ("role_escalation", re.compile(r"\b(as|i am|i'm|act as|pretend)\b.{0,20}\b(an? )?(admin|administrator|root|superuser)\b", re.I)),
    ("tenant_switch", re.compile(r"\b(as|for|in|of|switch to)\b.{0,15}\bTENANT_[A-Z0-9_]+", re.I)),
    ("prompt_exfiltration", re.compile(r"\b(reveal|show|print|repeat|leak)\b.{0,25}\b(system prompt|your instructions|hidden prompt|api key|secret|token)\b", re.I | re.S)),
    ("bypass_security", re.compile(r"\b(bypass|disable|skip|turn off)\b.{0,25}\b(auth\w*|opa|polic\w*|guardrails?|approval|audit\w*)\b", re.I | re.S)),
]

_SECRETS = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*", re.I)),
    ("api_key", re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{16,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)),
    ("password_assignment", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}")),
]


@dataclass
class Scan:
    flags: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.flags


class GuardrailBlocked(Exception):
    def __init__(self, flags: list[str]):
        super().__init__(",".join(flags))
        self.flags = flags


class Guardrails:
    def __init__(self, mode: str = "monitor"):
        self.mode = mode if mode in ("off", "monitor", "block") else "monitor"

    def check_input(self, message: str) -> Scan:
        """Flags suspicious user input. In block mode the caller must refuse when `flags` is non-empty."""
        if self.mode == "off":
            return Scan()
        flags = [name for name, rx in _INJECTION if rx.search(message)]
        if len(message) > MAX_INPUT_CHARS:
            flags.append("oversized_input")
        return Scan(flags)

    def enforce_input(self, message: str) -> Scan:
        scan = self.check_input(message)
        if self.mode == "block" and scan.flags:
            raise GuardrailBlocked(scan.flags)
        return scan

    def scan_untrusted_text(self, text: str) -> list[str]:
        """Retrieved documents are DATA, never instructions. Flags text that tries to instruct the model."""
        if self.mode == "off":
            return []
        return [n for n, rx in _INJECTION if rx.search(text)]

    def redact(self, text: str) -> tuple[str, list[str]]:
        """Masks secrets in anything leaving the platform (replies). Always active unless mode == off."""
        if self.mode == "off" or not text:
            return text, []
        hits = []
        for name, rx in _SECRETS:
            if rx.search(text):
                hits.append(f"redacted_{name}")
                text = rx.sub("[REDACTED]", text)
        return text, hits
