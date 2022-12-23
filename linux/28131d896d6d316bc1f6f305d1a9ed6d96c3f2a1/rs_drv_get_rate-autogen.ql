/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_drv_get_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rs-drv-get-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_drv_get_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_2724, Variable vlq_sta_2725) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("iwl_mvm_hwrate_to_tx_rate")
		and not target_0.getTarget().hasName("iwl_mvm_hwrate_to_tx_rate_v1")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="last_rate_n_flags"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlq_sta_2725
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="band"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2724
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="rates"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="control"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2724
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_1(Parameter vtxrc_2719, Variable vinfo_2724, Variable vlast_ucode_rate_2727) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("iwl_mvm_hwrate_to_tx_rate")
		and not target_1.getTarget().hasName("iwl_mvm_hwrate_to_tx_rate_v1")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vlast_ucode_rate_2727
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="band"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2724
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="reported_rate"
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtxrc_2719)
}

from Function func, Parameter vtxrc_2719, Variable vinfo_2724, Variable vlq_sta_2725, Variable vlast_ucode_rate_2727
where
func_0(vinfo_2724, vlq_sta_2725)
and func_1(vtxrc_2719, vinfo_2724, vlast_ucode_rate_2727)
and vtxrc_2719.getType().hasName("ieee80211_tx_rate_control *")
and vinfo_2724.getType().hasName("ieee80211_tx_info *")
and vlq_sta_2725.getType().hasName("iwl_lq_sta *")
and vlast_ucode_rate_2727.getType().hasName("u32")
and vtxrc_2719.getParentScope+() = func
and vinfo_2724.getParentScope+() = func
and vlq_sta_2725.getParentScope+() = func
and vlast_ucode_rate_2727.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
