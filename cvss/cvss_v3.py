from abc import abstractmethod
from typing import Self

from abs.abc_cvss import AbcCvss, AbcVector, CvssVersion

from dataclasses import dataclass, field
import numpy as np
import re

cvss_v3_regex_pattern = re.compile(
    r"^CVSS:\d\.\d/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH](/E:[PXUFH])?(/RL:[OTXUW])?(/RC:[URCX])?$")


class AttackVector(AbcVector):
    NETWORK = ["NETWORK", "N", 0.85]
    ADJACENT_NETWORK = ["ADJACENT_NETWORK", "A", 0.62]
    LOCAL = ["LOCAL", "L", 0.55]
    PHYSICAL = ["PHYSICAL", "P", 0.2]

    def to_str(self, value="AV"):
        return super().to_str(value)


class ModifiedAttackVector(AbcVector):
    NETWORK = ["NETWORK", "N", 0.85]
    ADJACENT_NETWORK = ["ADJACENT_NETWORK", "A", 0.62]
    LOCAL = ["LOCAL", "L", 0.55]
    PHYSICAL = ["PHYSICAL", "P", 0.2]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="MAV"):
        return super().to_str(value)


class AttackComplexity(AbcVector):
    HIGH = ["HIGH", "H", 0.44]
    LOW = ["LOW", "L", 0.77]

    def to_str(self, value="AC"):
        return super().to_str(value)


class ModifiedAttackComplexity(AbcVector):
    HIGH = ["HIGH", "H", 0.44]
    LOW = ["LOW", "L", 0.77]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="MAC"):
        return super().to_str(value)


class Scope(AbcVector):
    UNCHANGED = ["UNCHANGED", "U", 0.0]
    CHANGED = ["CHANGED", "C", 1.0]

    def to_str(self, value="S"):
        return super().to_str(value)


class ModifiedScope(AbcVector):
    UNCHANGED = ["UNCHANGED", "U", 0.0]
    CHANGED = ["CHANGED", "C", 1.0]
    NOT_DEFINED = ["NOT_DEFINED", "X", -1.0]

    def to_str(self, value="MS"):
        return super().to_str(value)


class PrivilegesRequired(AbcVector):
    HIGH = ["HIGH", "H", 0.27, 0.5]  # 0.5 if Scope or ModifiedScope = Changed
    LOW = ["LOW", "L", 0.62, 0.68]  # 0.68 if Scope or ModifiedScope = Changed
    NONE = ["NONE", "N", 0.85]

    def to_str(self, value="PR"):
        return super().to_str(value)

    def to_float(self, scope: Scope) -> float:
        if self == PrivilegesRequired.NONE or scope == Scope.UNCHANGED:
            return self.value[2]
        return self.value[3]


class ModifiedPrivilegesRequired(AbcVector):
    HIGH = ["HIGH", "H", 0.27, 0.5]  # 0.5 if Scope or ModifiedScope = Changed
    LOW = ["LOW", "L", 0.62, 0.68]  # 0.68 if Scope or ModifiedScope = Changed
    NONE = ["NONE", "N", 0.85]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="PR"):
        return super().to_str(value)

    def to_float(self, scope: Scope) -> float:
        if self.value == PrivilegesRequired.NONE or scope == Scope.UNCHANGED:
            return self.value[2]
        return self.value[3]


class UserInteraction(AbcVector):
    NONE = ["NONE", "N", 0.85]
    REQUIRED = ["REQUIRED", "R", 0.62]

    def to_str(self, value="UI"):
        return super().to_str(value)


class ModifiedUserInteraction(AbcVector):
    NONE = ["NONE", "N", 0.85]
    REQUIRED = ["REQUIRED", "R", 0.62]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="MUI"):
        return super().to_str(value)


class ConfidentialityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]

    def to_str(self, value="C"):
        return super().to_str(value)


class ModifiedConfidentialityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]
    NOT_DEFINED = ["NOT_DEFINED", "X", 0.0]

    def to_str(self, value="MC"):
        return super().to_str(value)


class IntegrityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]

    def to_str(self, value="I"):
        return super().to_str(value)


class ModifiedIntegrityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]
    NOT_DEFINED = ["NOT_DEFINED", "X", 0.0]

    def to_str(self, value="MI"):
        return super().to_str(value)


class AvailabilityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]

    def to_str(self, value="A") -> str:
        return super().to_str(value)


class ModifiedAvailabilityImpact(AbcVector):
    NONE = ["NONE", "N", 0.0]
    LOW = ["LOW", "L", 0.22]
    HIGH = ["HIGH", "H", 0.56]
    NOT_DEFINED = ["NOT_DEFINED", "X", 0.0]

    def to_str(self, value="MA") -> str:
        return super().to_str(value)


class ExploitCodeMaturity(AbcVector):
    UNPROVEN = ["UNPROVEN", "U", 0.91]
    PROOF_OF_CONCEPT = ["PROOF_OF_CONCEPT", "P", 0.94]
    FUNCTIONAL = ["FUNCTIONAL", "F", 0.97]
    HIGH = ["HIGH", "H", 1.0]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="E"):
        return super().to_str(value)


class RemediationLevel(AbcVector):
    OFFICIAL_FIX = ["OFFICIAL_FIX", "O", 0.95]
    TEMPORARY_FIX = ["TEMPORARY_FIX", "T", 0.96]
    WORKAROUND = ["WORKAROUND", "W", 0.97]
    UNAVAILABLE = ["UNAVAILABLE", "U", 1.0]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="RL"):
        return super().to_str(value)


class ReportConfidence(AbcVector):
    UNKNOWN = ["UNKNOWN", "U", 0.92]
    REASONABLE = ["REASONABLE", "R", 0.96]
    CONFIRMED = ["CONFIRMED", "C", 1.0]
    NOT_DEFINED = ["NOT_DEFINED", "X", 1.0]

    def to_str(self, value="RC"):
        return super().to_str(value)


class ConfidentialityRequirement(AbcVector):
    NOT_DEFINED = ["NOT_DEFINED", "X", 1]
    LOW = ["LOW", "L", 1.5]
    MEDIUM = ["MEDIUM", "M", 1]
    HIGH = ["HIGH", "H", 0.5]

    def to_str(self, value="CR"):
        return super().to_str(value)


class IntegrityRequirement(AbcVector):
    NOT_DEFINED = ["NOT_DEFINED", "X", 1]
    LOW = ["LOW", "L", 1.5]
    MEDIUM = ["MEDIUM", "M", 1]
    HIGH = ["HIGH", "H", 0.5]

    def to_str(self, value="IR"):
        return super().to_str(value)


class AvailabilityRequirement(AbcVector):
    NOT_DEFINED = ["NOT_DEFINED", "X", 1]
    LOW = ["LOW", "L", 1.5]
    MEDIUM = ["MEDIUM", "M", 1]
    HIGH = ["HIGH", "H", 0.5]

    def to_str(self, value="AR"):
        return super().to_str(value)


@dataclass
class CvssV3(AbcCvss):

    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality_impact: ConfidentialityImpact
    integrity_impact: IntegrityImpact
    availability_impact: AvailabilityImpact
    exploit_code_maturity: ExploitCodeMaturity = field(default=ExploitCodeMaturity.NOT_DEFINED)
    remediation_level: RemediationLevel = field(default=RemediationLevel.NOT_DEFINED)
    report_confidence: ReportConfidence = field(default=ReportConfidence.NOT_DEFINED)
    mod_attack_vector: ModifiedAttackVector = field(default=ModifiedAttackVector.NOT_DEFINED)
    mod_attack_complexity: ModifiedAttackComplexity = field(default=ModifiedAttackComplexity.NOT_DEFINED)
    mod_privileges_required: ModifiedPrivilegesRequired = field(default=ModifiedPrivilegesRequired.NOT_DEFINED)
    mod_user_interaction: ModifiedUserInteraction = field(default=ModifiedUserInteraction.NOT_DEFINED)
    mod_scope: ModifiedScope = field(default=ModifiedScope.NOT_DEFINED)
    mod_confidentiality_impact: ModifiedConfidentialityImpact = field(default=ModifiedConfidentialityImpact.NOT_DEFINED)
    mod_integrity_impact: ModifiedIntegrityImpact = field(default=ModifiedIntegrityImpact.NOT_DEFINED)
    mod_availability_impact: ModifiedAvailabilityImpact = field(default=ModifiedAvailabilityImpact.NOT_DEFINED)
    confidentiality_requirement: ConfidentialityRequirement = field(default=ConfidentialityRequirement.NOT_DEFINED)
    integrity_requirement: IntegrityRequirement = field(default=IntegrityRequirement.NOT_DEFINED)
    availability_requirement: AvailabilityRequirement = field(default=AvailabilityRequirement.NOT_DEFINED)

    @classmethod
    def from_vector_string(cls, value: str):
        # if cvss_v3_regex_pattern.match(value) is None:
        #     raise Exception  # TODO create exception
        metrics = cls.parse_vector_string(value)
        v = CvssVersion.from_str(metrics.get('CVSS'))
        av = AttackVector.from_char(metrics.get('AV'))
        ac = AttackComplexity.from_char(metrics.get('AC'))
        pr = PrivilegesRequired.from_char(metrics.get('PR'))
        ui = UserInteraction.from_char(metrics.get('UI'))
        s = Scope.from_char(metrics.get('S'))
        c = ConfidentialityImpact.from_char(metrics.get('C'))
        i = IntegrityImpact.from_char(metrics.get('I'))
        a = AvailabilityImpact.from_char(metrics.get('A'))
        e = ExploitCodeMaturity.from_char(metrics.get('E', 'X'))
        rl = RemediationLevel.from_char(metrics.get('RL', 'X'))
        rc = ReportConfidence.from_char(metrics.get('RC', 'X'))
        mav = ModifiedAttackVector.from_char(metrics.get('MAV', 'X'))
        mac = ModifiedAttackComplexity.from_char(metrics.get('MAC', 'X'))
        mpr = ModifiedPrivilegesRequired.from_char(metrics.get('MPR', 'X'))
        mui = ModifiedUserInteraction.from_char(metrics.get('MUI', 'X'))
        ms = ModifiedScope.from_char(metrics.get('MS', 'X'))
        mc = ModifiedConfidentialityImpact.from_char(metrics.get('MC', 'X'))
        mi = ModifiedIntegrityImpact.from_char(metrics.get('MI', 'X'))
        ma = ModifiedAvailabilityImpact.from_char(metrics.get('MA', 'X'))
        cr = ConfidentialityRequirement.from_char(metrics.get('CR', 'X'))
        ir = IntegrityRequirement.from_char(metrics.get('IR', 'X'))
        ar = AvailabilityRequirement.from_char(metrics.get('AR', 'X'))
        return cls(version=v,
                   attack_vector=av,
                   attack_complexity=ac,
                   privileges_required=pr,
                   user_interaction=ui,
                   scope=s,
                   confidentiality_impact=c,
                   integrity_impact=i,
                   availability_impact=a,
                   exploit_code_maturity=e,
                   remediation_level=rl,
                   report_confidence=rc,
                   mod_attack_vector=mav,
                   mod_attack_complexity=mac,
                   mod_privileges_required=mpr,
                   mod_user_interaction=mui,
                   mod_scope=ms,
                   mod_confidentiality_impact=mc,
                   mod_integrity_impact=mi,
                   mod_availability_impact=ma,
                   confidentiality_requirement=cr,
                   integrity_requirement=ir,
                   availability_requirement=ar)

    @classmethod
    def from_primitive_dict(cls, value: dict) -> Self:
        value_0: dict = value[0]['cvssData']
        v = CvssVersion.from_str(value_0['version'])
        av = AttackVector.from_str(value_0['attackVector'])
        ac = AttackComplexity.from_str(value_0['attackComplexity'])
        pr = PrivilegesRequired.from_str(value_0['privilegesRequired'])
        ui = UserInteraction.from_str(value_0['userInteraction'])
        s = Scope.from_str(value_0['scope'])
        c = ConfidentialityImpact.from_str(value_0['confidentialityImpact'])
        i = IntegrityImpact.from_str(value_0['integrityImpact'])
        a = AvailabilityImpact.from_str(value_0['availabilityImpact'])
        e = ExploitCodeMaturity.from_str(value_0.get('exploitCodeMaturity', 'NOT_DEFINED'))
        rl = RemediationLevel.from_str(value_0.get('remediationLevel', 'NOT_DEFINED'))
        rc = ReportConfidence.from_str(value_0.get('reportConfidence', 'NOT_DEFINED'))
        mav = ModifiedAttackVector.from_str(value_0.get('modifiedAttackVector', 'NOT_DEFINED'))
        mac = ModifiedAttackComplexity.from_str(value_0.get('modifiedAttackComplexity', 'NOT_DEFINED'))
        mpr = ModifiedPrivilegesRequired.from_str(value_0.get('modifiedPrivilegesRequired', 'NOT_DEFINED'))
        mui = ModifiedUserInteraction.from_str(value_0.get('modifiedUserInteraction', 'NOT_DEFINED'))
        ms = ModifiedScope.from_str(value_0.get('modifiedScope', 'NOT_DEFINED'))
        mc = ModifiedConfidentialityImpact.from_str(value_0.get('modifiedConfidentialityImpact', 'NOT_DEFINED'))
        mi = ModifiedIntegrityImpact.from_str(value_0.get('modifiedIntegrityImpact', 'NOT_DEFINED'))
        ma = ModifiedAvailabilityImpact.from_str(value_0.get('modifiedAvailabilityImpact', 'NOT_DEFINED'))
        cr = ConfidentialityRequirement.from_str(value_0.get('confidentialityRequirement', 'NOT_DEFINED'))
        ir = IntegrityRequirement.from_str(value_0.get('integrityRequirement', 'NOT_DEFINED'))
        ar = AvailabilityRequirement.from_str(value_0.get('availabilityRequirement', 'NOT_DEFINED'))
        return cls(version=v,
                   attack_vector=av,
                   attack_complexity=ac,
                   privileges_required=pr,
                   user_interaction=ui,
                   scope=s,
                   confidentiality_impact=c,
                   integrity_impact=i,
                   availability_impact=a,
                   exploit_code_maturity=e,
                   remediation_level=rl,
                   report_confidence=rc,
                   mod_attack_vector=mav,
                   mod_attack_complexity=mac,
                   mod_privileges_required=mpr,
                   mod_user_interaction=mui,
                   mod_scope=ms,
                   mod_confidentiality_impact=mc,
                   mod_integrity_impact=mi,
                   mod_availability_impact=ma,
                   confidentiality_requirement=cr,
                   integrity_requirement=ir,
                   availability_requirement=ar)

    def __post_init__(self):
        base_score = self._compute_base_score()
        self.set_base_score(base_score)
        self.set_base_severity(base_score)

        env_score = self._compute_env_score()
        self.set_env_score(env_score)

        self._vector_string = self._compute_vector_string()

    def set_mod_attack_vector(self, value: ModifiedAttackVector) -> None:
        self.mod_attack_vector = value
        self.set_env_score(self._compute_env_score())

    def set_mod_privileges_required(self, value: ModifiedPrivilegesRequired) -> None:
        self.mod_privileges_required = value
        self.set_env_score(self._compute_env_score())

    def set_confidentiality_requirement(self, value: ConfidentialityRequirement) -> None:
        self.confidentiality_requirement = value
        self.set_env_score(self._compute_env_score())

    def set_integrity_requirement(self, value: IntegrityRequirement) -> None:
        self.integrity_requirement = value
        self.set_env_score(self._compute_env_score())

    def set_availability_requirement(self, value: AvailabilityRequirement) -> None:
        self.availability_requirement = value
        self.set_env_score(self._compute_env_score())

    def to_primitive_dict(self) -> dict:
        return {
            'vectorString': self.get_vector_string(),
            'attackVector': self.attack_vector.to_str(),
            'attackComplexity': self.attack_complexity.to_str(),
            'privilegesRequired': self.privileges_required.to_str(),
            'userInteraction': self.user_interaction.to_str(),
            'scope': self.scope.to_str(),
            'confidentialityImpact': self.confidentiality_impact.to_str(),
            'integrityImpact': self.integrity_impact.to_str(),
            'availabilityImpact': self.availability_impact.to_str(),
            'exploitCodeMaturity': self.exploit_code_maturity.to_str(),
            'remediationLevel': self.remediation_level.to_str(),
            'reportConfidence': self.report_confidence.to_str(),
            'modifiedAttackVector': self.mod_attack_vector.to_str(),
            'modifiedAttackComplexity': self.mod_attack_complexity.to_str(),
            'modifiedPrivilegesRequired': self.mod_privileges_required.to_str(),
            'modifiedUserInteraction': self.mod_user_interaction.to_str(),
            'modifiedScope': self.mod_scope.to_str(),
            'modifiedConfidentialityImpact': self.mod_confidentiality_impact.to_str(),
            'modifiedIntegrityImpact': self.mod_integrity_impact.to_str(),
            'modifiedAvailabilityImpact': self.mod_availability_impact.to_str(),
            'confidentialityRequirement': self.confidentiality_requirement.to_str(),
            'integrityRequirement': self.integrity_requirement.to_str(),
            'availabilityRequirement': self.availability_requirement.to_str(),
            'baseScore': self.get_base_score(),
            'baseSeverity': self.get_base_severity()
        }

    def _compute_vector_string(self) -> str:
        """
        Return the Vector String
        Example: /AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N
        :return: str
        """
        return (self.attack_vector.to_str() +
                self.attack_complexity.to_str() +
                self.privileges_required.to_str() +
                self.user_interaction.to_str() +
                self.scope.to_str() +
                self.confidentiality_impact.to_str() +
                self.integrity_impact.to_str() +
                self.availability_impact.to_str() +
                self.exploit_code_maturity.to_str() +
                self.remediation_level.to_str() +
                self.report_confidence.to_str() +
                self.mod_attack_vector.to_str() +
                self.mod_attack_complexity.to_str() +
                self.mod_privileges_required.to_str() +
                self.mod_user_interaction.to_str() +
                self.mod_scope.to_str() +
                self.mod_confidentiality_impact.to_str() +
                self.mod_integrity_impact.to_str() +
                self.mod_availability_impact.to_str() +
                self.confidentiality_requirement.to_str() +
                self.integrity_requirement.to_str() +
                self.availability_requirement.to_str())

    def _compute_isc(self) -> float:
        conf_impact: float = self.confidentiality_impact.to_float()
        int_impact: float = self.integrity_impact.to_float()
        avail_impact: float = self.availability_impact.to_float()
        return 1 - ((1 - conf_impact) * (1 - int_impact) * (1 - avail_impact))

    def _compute_base_score(self) -> float:
        if self.scope == Scope.UNCHANGED:
            return CvssV3.roundup(min(self._compute_impact_score() + self._compute_exploitability_score(), 10))
        return CvssV3.roundup(min(1.08 * (self._compute_impact_score() + self._compute_exploitability_score()), 10))

    def _compute_exploitability_score(self) -> float:
        attack_vector: float = self.attack_vector.to_float()
        attack_complexity: float = self.attack_complexity.to_float()
        priv_required: float = self.privileges_required.to_float(self.scope)
        user_interaction: float = self.user_interaction.to_float()
        return 8.22 * attack_vector * attack_complexity * priv_required * user_interaction

    def _compute_impact_score(self) -> float:
        isc = self._compute_isc()
        if self.scope == Scope.UNCHANGED:
            return 6.42 * isc
        return (7.52 * (isc - 0.029)) - (3.25 * pow((isc - 0.02), 15))

    def _compute_temporal_score(self) -> float:
        return CvssV3.roundup(self.get_base_score() *
                              self.exploit_code_maturity.to_float() *
                              self.remediation_level.to_float() *
                              self.report_confidence.to_float())

    @abstractmethod
    def _compute_env_score(self) -> float:
        pass

    @staticmethod
    def roundup(value: float) -> float:
        int_value = np.rint(value * 100000)
        if int_value % 10000 == 0:
            return int_value / 100000.0
        else:
            return (np.floor(int_value / 10000) + 1) / 10.0
