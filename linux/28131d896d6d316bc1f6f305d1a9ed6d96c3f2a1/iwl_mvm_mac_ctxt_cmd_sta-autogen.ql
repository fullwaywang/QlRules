/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_ctxt_cmd_sta
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-mac-ctxt-cmd-sta
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_ctxt_cmd_sta CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctxt_sta_548, Variable vmvmvif_569, Parameter vmvm_542, Parameter vvif_543, Parameter vforce_assoc_off_544) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="authorized"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvmvif_569
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("fw_has_capa")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fw"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_542
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_policy"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_sta_548
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="assoc"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_543
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="dtim_period"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_543
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vforce_assoc_off_544)
}

predicate func_1(Variable vctxt_sta_548) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="is_assoc"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctxt_sta_548)
}

predicate func_2(Variable vmvmvif_569) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="ap_sta_id"
		and target_2.getQualifier().(VariableAccess).getTarget()=vmvmvif_569)
}

predicate func_3(Parameter vmvm_542) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="dev"
		and target_3.getQualifier().(VariableAccess).getTarget()=vmvm_542)
}

from Function func, Variable vctxt_sta_548, Variable vmvmvif_569, Parameter vmvm_542, Parameter vvif_543, Parameter vforce_assoc_off_544
where
not func_0(vctxt_sta_548, vmvmvif_569, vmvm_542, vvif_543, vforce_assoc_off_544)
and vctxt_sta_548.getType().hasName("iwl_mac_data_sta *")
and func_1(vctxt_sta_548)
and vmvmvif_569.getType().hasName("iwl_mvm_vif *")
and func_2(vmvmvif_569)
and vmvm_542.getType().hasName("iwl_mvm *")
and func_3(vmvm_542)
and vvif_543.getType().hasName("ieee80211_vif *")
and vforce_assoc_off_544.getType().hasName("bool")
and vctxt_sta_548.getParentScope+() = func
and vmvmvif_569.getParentScope+() = func
and vmvm_542.getParentScope+() = func
and vvif_543.getParentScope+() = func
and vforce_assoc_off_544.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
