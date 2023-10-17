from dataclasses import dataclass, field
from typing import Any, Callable
import numpy as np
import re

from abs.abc_cvss import AbcCvss, AbcVector, CvssVersion

cvss_v2_regex_pattern = re.compile(r"^AV:[N,AL]/AC:[MLH]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC](/E:(POC|ND|[UFH]))?(/RL:(OF|TF|ND|[UW]))?(/RC:(UC|UR|ND|C))?$")
# CVSS_V2_METRIC_REGEX_PATTERN = re.compile(r'(?<=:)[A-Za-z]+')


class AccessVector(AbcVector):
    NETWORK = ['NETWORK', 'N', 1.0]
    ADJACENT_NETWORK = ['ADJACENT_NETWORK', 'A', 0.646]
    LOCAL = ['LOCAL', 'L', 0.395]

    def to_str(self, value='AV'):
        return super().to_str(value)


class AccessComplexity(AbcVector):
    HIGH = ["HIGH", "H", 0.35]
    MEDIUM = ["MEDIUM", "M", 0.61]
    LOW = ["LOW", "L", 0.71]

    def to_str(self, value='AC'):
        return super().to_str(value)


class Authentication(AbcVector):
    MULTIPLE = ["MULTIPLE", "M", 0.45]
    SINGLE = ["SINGLE", "S", 0.56]
    NONE = ["NONE", "N", 0.704]

    def to_str(self, value='Au'):
        return super().to_str(value)


class ConfidentialityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    PARTIAL = ["PARTIAL", "P", 0.275]
    COMPLETE = ["COMPLETE", "C", 0.660]

    def to_str(self, value='C'):
        return super().to_str(value)


class IntegrityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    PARTIAL = ["PARTIAL", "P", 0.275]
    COMPLETE = ["COMPLETE", "C", 0.660]

    def to_str(self, value='I'):
        return super().to_str(value)


class AvailabilityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    PARTIAL = ["PARTIAL", "P", 0.275]
    COMPLETE = ["COMPLETE", "C", 0.660]

    def to_str(self, value='A'):
        return super().to_str(value)


class Exploitability(AbcVector):
    UNPROVEN = ["UNPROVEN", "U", 0.85]
    PROOF_OF_CONCEPT = ["PROOF_OF_CONCEPT", "POC", 0.9]
    FUNCTIONAL = ["FUNCTIONAL", "F", 0.95]
    HIGH = ["HIGH", "H", 1.0]
    NOT_DEFINED = ["NOT_DEFINED", "ND", 1.0]

    def to_str(self, value='E'):
        return super().to_str(value)


class RemediationLevel(AbcVector):
    OFFICIAL_FIX = ["OFFICIAL_FIX", "OF", 0.87]
    TEMPORARY_FIX = ["TEMPORARY_FIX", "TF", 0.90]
    WORKAROUND = ["WORKAROUND", "W", 0.95]
    UNAVAILABLE = ["UNAVAILABLE", "U", 1.00]
    NOT_DEFINED = ["NOT_DEFINED", "ND", 1.00]

    def to_str(self, value='RL'):
        return super().to_str(value)


class ReportConfidence(AbcVector):
    UNCONFIRMED = ["UNCONFIRMED", "UC", 0.90]
    UNCORROBORATED = ["UNCORROBORATED", "UR", 0.95]
    CONFIRMED = ["CONFIRMED", "C", 1.00]
    NOT_DEFINED = ["NOT_DEFINED", "ND", 1.00]

    def to_str(self, value='RC'):
        return super().to_str(value)


@dataclass
class CvssV2(AbcCvss):
    access_vector: AccessVector
    access_complexity: AccessComplexity
    authentication: Authentication
    confidentiality_impact: ConfidentialityImpact
    integrity_impact: IntegrityImpact
    availability_impact: AvailabilityImpact
    exploitability: Exploitability = field(default=Exploitability.NOT_DEFINED)
    remediation_level: RemediationLevel = field(default=RemediationLevel.NOT_DEFINED)
    report_confidence: ReportConfidence = field(default=ReportConfidence.NOT_DEFINED)

    @classmethod
    def from_vector_string(cls, value: str):
        if cvss_v2_regex_pattern.match(value) is None:
            raise Exception  # TODO create exception
        metrics = cls.parse_vector_string(value)
        av = AccessVector.from_char(metrics.get('AV'))
        ac = AccessComplexity.from_char(metrics.get('AC'))
        au = Authentication.from_char(metrics.get('Au'))
        c = ConfidentialityImpact.from_char(metrics.get('C'))
        i = IntegrityImpact.from_char(metrics.get('I'))
        a = AvailabilityImpact.from_char(metrics.get('A'))
        e = Exploitability.from_char(metrics.get('E', 'ND'))
        rl = RemediationLevel.from_char(metrics.get('RL', 'ND'))
        rc = ReportConfidence.from_char(metrics.get('RC', 'ND'))
        return cls(version=CvssVersion.CVSS_V2,
                   access_vector=av,
                   access_complexity=ac,
                   authentication=au,
                   confidentiality_impact=c,
                   integrity_impact=i,
                   availability_impact=a,
                   exploitability=e,
                   remediation_level=rl,
                   report_confidence=rc)

    @classmethod
    def from_primitive_dict(cls, value: dict):
        value_0: dict = value[0]['cvssData']
        av = AccessVector.from_str(value_0['accessVector'])
        ac = AccessComplexity.from_str(value_0['accessComplexity'])
        au = Authentication.from_str(value_0['authentication'])
        c = ConfidentialityImpact.from_str(value_0['confidentialityImpact'])
        i = IntegrityImpact.from_str(value_0['integrityImpact'])
        a = AvailabilityImpact.from_str(value_0['availabilityImpact'])
        e = Exploitability.from_str(value_0.get('exploitability', 'NOT_DEFINED'))
        rl = RemediationLevel.from_str(value_0.get('remediationLevel', 'NOT_DEFINED'))
        rc = ReportConfidence.from_str(value_0.get('reportConfidence', 'NOT_DEFINED'))
        return cls(version=CvssVersion.CVSS_V2,
                   access_vector=av,
                   access_complexity=ac,
                   authentication=au,
                   confidentiality_impact=c,
                   integrity_impact=i,
                   availability_impact=a,
                   exploitability=e,
                   remediation_level=rl,
                   report_confidence=rc)

    def __post_init__(self):
        base_score = self._compute_base_score()
        self.set_base_score(base_score)
        self.set_base_severity(base_score)
        self._vector_string = self._compute_vector_string()

    def to_primitive_dict(self) -> dict[str | Any, str | Any]:
        return {
            'vectorString': self.get_vector_string(),
            'accessVector': self.access_vector.to_str(),
            'accessComplexity': self.access_complexity.to_str(),
            'authentication': self.authentication.to_str(),
            'confidentialityImpact': self.confidentiality_impact.to_str(),
            'integrityImpact': self.integrity_impact.to_str(),
            'availabilityImpact': self.availability_impact.to_str(),
            'exploitability': self.exploitability.to_str(),
            'remediationLevel': self.remediation_level.to_str(),
            'reportConfidence': self.report_confidence.to_str(),
            'baseScore': self.get_base_score(),
            'baseSeverity': self.get_base_severity()
        }

    def _compute_vector_string(self) -> str:
        """
        Set the Vector String
        Example: AV:L/AC:L/Au:N/C:C/I:C/A:C
        :return: None
        """
        return (self.access_vector.to_str() +
                self.access_complexity.to_str() +
                self.authentication.to_str() +
                self.confidentiality_impact.to_str() +
                self.integrity_impact.to_str() +
                self.availability_impact.to_str() +
                self.exploitability.to_str() +
                self.remediation_level.to_str() +
                self.report_confidence.to_str())

    def _compute_base_score(self) -> float:
        cis = self._compute_impact_score()
        ces = self._compute_exploitability_score()
        return self.round_to_one_decimal(((0.6 * cis) + (0.4 * ces) - 1.5) * self._f(self._compute_impact_score))

    def _compute_exploitability_score(self) -> float:
        access_vector: float = self.access_vector.to_float()
        access_complexity: float = self.access_complexity.to_float()
        authentication: float = self.authentication.to_float()
        return 20 * access_vector * access_complexity * authentication

    def _compute_impact_score(self) -> float:
        conf_impact: float = self.confidentiality_impact.to_float()
        int_impact: float = self.integrity_impact.to_float()
        avail_impact: float = self.availability_impact.to_float()
        return 10.41 * (1 - (1 - conf_impact) * (1 - int_impact) * (1 - avail_impact))

    def _f(self, impact: Callable) -> float:
        if impact() == 0.0:
            return 0.0
        else:
            return 1.176

    def _compute_temporal_score(self) -> float:
        return np.round(self.get_base_score() *
                        self.exploitability.to_float() *
                        self.remediation_level.to_float() *
                        self.report_confidence.to_float())

    def _compute_env_score(self) -> float:
        return 666

    @staticmethod
    def round_to_one_decimal(f: float) -> float:
        return round(f, 1)
