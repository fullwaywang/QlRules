/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_legacy_rate_to_mac80211_idx
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-legacy-rate-to-mac80211-idx
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_legacy_rate_to_mac80211_idx CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vidx_163) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("iwl_fw_rate_idx_to_plcp")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vidx_163)
}

predicate func_2(Variable vrate_162, Variable vidx_163, Variable vband_offset_164, Variable vfw_rate_idx_to_plcp) {
	exists(ArrayExpr target_2 |
		target_2.getArrayBase().(VariableAccess).getTarget()=vfw_rate_idx_to_plcp
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vidx_163
		and target_2.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vrate_162
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vidx_163
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vband_offset_164)
}

from Function func, Variable vrate_162, Variable vidx_163, Variable vband_offset_164, Variable vfw_rate_idx_to_plcp
where
not func_0(vidx_163)
and func_2(vrate_162, vidx_163, vband_offset_164, vfw_rate_idx_to_plcp)
and vrate_162.getType().hasName("int")
and vidx_163.getType().hasName("int")
and vband_offset_164.getType().hasName("int")
and vfw_rate_idx_to_plcp.getType().hasName("const u8[17]")
and vrate_162.getParentScope+() = func
and vidx_163.getParentScope+() = func
and vband_offset_164.getParentScope+() = func
and not vfw_rate_idx_to_plcp.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
