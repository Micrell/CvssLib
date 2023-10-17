from cvss.cvss_v3 import CvssV3, ModifiedScope, Scope


class CvssV31(CvssV3):

    def _compute_mod_exploitability_score(self) -> float:
        s = self.mod_scope if self.mod_scope else self.scope
        mav = self.mod_attack_vector.to_float() if self.mod_attack_vector else self.attack_vector.to_float()
        mac = self.mod_attack_complexity.to_float() if self.mod_attack_complexity else self.attack_complexity.to_float()
        mpr = self.mod_privileges_required.to_float(s) if self.mod_privileges_required else self.privileges_required.to_float(s)
        mui = self.mod_user_interaction.to_float() if self.mod_user_interaction else self.user_interaction.to_float()
        return 8.22 * mav * mac * mpr * mui

    def _compute_mod_isc(self) -> float:
        mc = self.mod_confidentiality_impact.to_float() if self.mod_confidentiality_impact else self.confidentiality_impact.to_float()
        mi = self.mod_integrity_impact.to_float() if self.mod_integrity_impact else self.integrity_impact.to_float()
        ma = self.mod_availability_impact.to_float() if self.mod_availability_impact else self.availability_impact.to_float()
        return min(1 - (1 - mc * self.confidentiality_requirement.to_float()) *
                   (1 - mi * self.integrity_requirement.to_float()) *
                   (1 - ma * self.availability_requirement.to_float()), 0.915)

    def _compute_mod_impact_score(self) -> float:
        isc: float = self._compute_mod_isc()
        scope = self.mod_scope if self.mod_scope else self.scope
        if scope is ModifiedScope.UNCHANGED or scope is Scope.UNCHANGED:
            return 6.42 * isc
        else:
            return 7.52 * (isc - 0.029) - 3.25 * pow((isc * 0.9731 - 0.02), 13)

    def _compute_env_score(self) -> float:
        scope = self.mod_scope if self.mod_scope else self.scope
        mod_impact_score = self._compute_mod_impact_score()
        if mod_impact_score <= 0:
            return 0
        else:
            if scope is ModifiedScope.UNCHANGED or scope is Scope.UNCHANGED:
                return self.roundup(
                    self.roundup(min(mod_impact_score + self._compute_mod_exploitability_score(), 10)) *
                    self.exploit_code_maturity.to_float() * self.remediation_level.to_float() * self.report_confidence.to_float())
            else:
                if scope is ModifiedScope.CHANGED or scope is Scope.CHANGED:
                    return self.roundup(self.roundup(
                        min(1.08 * (mod_impact_score + self._compute_mod_exploitability_score()), 10)) *
                                        self.exploit_code_maturity.to_float() * self.remediation_level.to_float() * self.report_confidence.to_float())
