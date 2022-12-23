/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_cfg_he_sta
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-cfg-he-sta
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_cfg_he_sta CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vvif_1994) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ieee80211_vif_type_p2p")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vvif_1994)
}

predicate func_3(Parameter vvif_1994) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="type"
		and target_3.getQualifier().(VariableAccess).getTarget()=vvif_1994)
}

from Function func, Parameter vvif_1994
where
not func_1(vvif_1994)
and func_3(vvif_1994)
and vvif_1994.getType().hasName("ieee80211_vif *")
and vvif_1994.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
