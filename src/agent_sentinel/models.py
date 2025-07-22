from enum import StrEnum
from typing import Any

cwe_mapping = {
    "B101": "CWE-78",  # assert_used
    "B102": "CWE-78",  # exec_used
    "B103": "CWE-78",  # set_bad_file_permissions
    "B104": "CWE-319", # hardcoded_bind_all_interfaces
    "B105": "CWE-259", # hardcoded_password_string
    "B106": "CWE-259", # hardcoded_password_funcarg
    "B107": "CWE-259", # hardcoded_password_default
    "B108": "CWE-377", # hardcoded_tmp_directory
    "B110": "CWE-78",  # try_except_pass
    "B112": "CWE-78",  # try_except_continue
    "B201": "CWE-78",  # flask_debug_true
    "B301": "CWE-502", # pickle
    "B302": "CWE-78",  # marshal
    "B303": "CWE-326", # md5
    "B304": "CWE-326", # insecure_cipher
    "B305": "CWE-326", # cipher_modes
    "B306": "CWE-327", # mktemp_q
    "B307": "CWE-78",  # eval
    "B308": "CWE-78",  # mark_safe
    "B309": "CWE-295", # httpsconnection
    "B310": "CWE-330", # urllib_urlopen
    "B311": "CWE-330", # random
    "B312": "CWE-78",  # telnetlib
    "B313": "CWE-78",  # xml_bad_cElementTree
    "B314": "CWE-78",  # xml_bad_ElementTree
    "B315": "CWE-78",  # xml_bad_expatreader
    "B316": "CWE-78",  # xml_bad_expatbuilder
    "B317": "CWE-78",  # xml_bad_sax
    "B318": "CWE-78",  # xml_bad_minidom
    "B319": "CWE-78",  # xml_bad_pulldom
    "B320": "CWE-78",  # xml_bad_etree
    "B321": "CWE-78",  # ftplib
    "B322": "CWE-78",  # input
    "B323": "CWE-295", # unverified_context
    "B324": "CWE-326", # hashlib_new_insecure_functions
    "B325": "CWE-377", # tempnam
    "B401": "CWE-78",  # import_telnetlib
    "B402": "CWE-78",  # import_ftplib
    "B403": "CWE-78",  # import_pickle
    "B404": "CWE-78",  # import_subprocess
    "B405": "CWE-78",  # import_xml_etree
    "B406": "CWE-78",  # import_xml_sax
    "B407": "CWE-78",  # import_xml_expat
    "B408": "CWE-78",  # import_xml_minidom
    "B409": "CWE-78",  # import_xml_pulldom
    "B410": "CWE-78",  # import_lxml
    "B411": "CWE-78",  # import_xmlrpclib
    "B412": "CWE-78",  # import_httpoxy
    "B413": "CWE-502", # import_pycrypto
    "B501": "CWE-295", # request_with_no_cert_validation
    "B502": "CWE-295", # ssl_with_bad_version
    "B503": "CWE-295", # ssl_with_bad_defaults
    "B504": "CWE-295", # ssl_with_no_version
    "B505": "CWE-326", # weak_cryptographic_key
    "B506": "CWE-78",  # yaml_load
    "B507": "CWE-78",  # ssh_no_host_key_verification
    "B601": "CWE-78",  # paramiko_calls
    "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",  # subprocess_without_shell_equals_false
    "B604": "CWE-78",  # any_other_function_with_shell_equals_true
    "B605": "CWE-78",  # start_process_with_a_shell
    "B606": "CWE-78",  # start_process_with_no_shell
    "B607": "CWE-78",  # start_process_with_partial_path
    "B608": "CWE-89",  # hardcoded_sql_expressions
    "B609": "CWE-78",  # linux_commands_wildcard_injection
    "B610": "CWE-78",  # django_extra_used
    "B611": "CWE-78",  # django_rawsql_used
    "B701": "CWE-78",  # jinja2_autoescape_false
    "B702": "CWE-78",  # use_of_mako_templates
    "B703": "CWE-78",  # django_mark_safe
}

class SeverityLevel(StrEnum):
    """
    Enumeration of security finding severity levels.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class Report:
    """
    Represents a security finding from various security scanning tools.
    """

    def __init__(
        self,
        tool: str,
        severity: str | SeverityLevel,
        description: str,
        file_path: str | None = None,
        line_number: str | None = None,
        language: str = "code",
        cwe: str = "n/a"
    ):
        """
        Initialize a security report.

        Args:
            tool: The security tool that found the issue (e.g., 'Slither', 'Semgrep', 'CodeQL')
            severity: The severity level (e.g., SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.CRITICAL)
            description: Description of the security issue
            file_path: Optional path to the file where the issue was found
            line_number: Optional line number(s) where the issue was found
            language: Programming language (default: "code")
            cwe: Common Weakness Enumeration identifier (default: "n/a")
        """
        self.tool = tool
        
        # Handle both string and SeverityLevel inputs
        if isinstance(severity, SeverityLevel):
            self.severity = severity
        elif isinstance(severity, str):
            # Try to match string to enum, fallback to UNKNOWN
            try:
                self.severity = SeverityLevel(severity.upper())
            except ValueError:
                self.severity = SeverityLevel.UNKNOWN
        else:
            self.severity = SeverityLevel.UNKNOWN
            
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.language = language
        self.cwe = cwe

    def __str__(self) -> str:
        """String representation of the report."""
        parts = [f"{self.tool} [{self.severity}]"]

        if self.file_path:
            parts.append(f"in {self.file_path}")

        if self.line_number:
            parts.append(f"line {self.line_number}")

        parts.append(f": {self.description}")

        return " ".join(parts)

    def __repr__(self) -> str:
        """Detailed representation of the report."""
        return f"Report(tool='{self.tool}', severity='{self.severity}', description='{self.description}', file_path='{self.file_path}', line_number='{self.line_number}', language='{self.language}', cwe='{self.cwe}')"

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a dictionary."""
        return {
            "tool": self.tool,
            "severity": str(self.severity),
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "language": self.language,
            "cwe": self.cwe
        }


class ErrorReport(Report):
    """
    Represents an error that occurred during security scanning.
    """

    def __init__(
        self,
        tool: str,
        reason: str
    ):
        """
        Initialize an error report.

        Args:
            tool: The security tool that encountered the error
            reason: Specific reason for the error
        """
        super().__init__(
            tool=tool,
            severity=SeverityLevel.ERROR,
            description=f"{tool} error: {reason}",
            file_path=None,
            line_number=None,
            language="code",
            cwe="n/a"
        )
        self.reason = reason

    def __repr__(self) -> str:
        """Detailed representation of the error report."""
        return f"ErrorReport(tool='{self.tool}', severity='{self.severity}', description='{self.description}', reason='{self.reason}', file_path='{self.file_path}', line_number='{self.line_number}', language='{self.language}', cwe='{self.cwe}')"

    def to_dict(self) -> dict[str, Any]:
        """Convert the error report to a dictionary."""
        result = super().to_dict()
        result["reason"] = self.reason
        return result

