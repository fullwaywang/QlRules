/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_sta_state
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-mac-sta-state
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_sta_state CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vsta_3068, Variable vmvmvif_3073) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="authorized"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvmvif_3073
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="tdls"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_3068)
}

predicate func_5(Parameter vvif_3067, Parameter vsta_3068, Parameter vold_state_3069, Parameter vnew_state_3070, Variable vmvm_3072, Variable vmvmvif_3073) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ap_assoc_sta_count"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvmvif_3073
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_mac_ctxt_changed")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_3067
		and target_5.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tdls"
		and target_5.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_3068
		and target_5.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_stop_session_protection")
		and target_5.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_5.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vold_state_3069
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_state_3070)
}

predicate func_7(Parameter vvif_3067, Parameter vsta_3068, Variable vmvm_3072) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_tdls_check_trigger")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_7.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="addr"
		and target_7.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_3068
		and target_7.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="tdls"
		and target_7.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_3068)
}

predicate func_8(Parameter vvif_3067, Parameter vold_state_3069, Parameter vnew_state_3070, Variable vmvm_3072) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_mac_ctxt_changed")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_8.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vold_state_3069
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_state_3070)
}

predicate func_10(Parameter vvif_3067, Parameter vold_state_3069, Parameter vnew_state_3070, Variable vmvm_3072, Variable vret_3075) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3075
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_mvm_disable_beacon_filter")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vold_state_3069
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_state_3070)
}

predicate func_11(Parameter vold_state_3069, Parameter vnew_state_3070, Variable vret_3075) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_3075
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vold_state_3069
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_state_3070)
}

predicate func_12(Parameter vvif_3067, Variable vmvm_3072, Variable vmvmvif_3073) {
	exists(EqualityOperation target_12 |
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_3067
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ap_assoc_sta_count"
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvmvif_3073
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_mac_ctxt_changed")
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_12.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_14(Parameter vvif_3067, Variable vmvm_3072) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("iwl_mvm_disable_beacon_filter")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_14.getArgument(1).(VariableAccess).getTarget()=vvif_3067
		and target_14.getArgument(2).(Literal).getValue()="0")
}

predicate func_15(Parameter vsta_3068, Variable vmvm_3072, Variable vmvmvif_3073) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("iwl_mvm_rs_rate_init")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vmvm_3072
		and target_15.getArgument(1).(VariableAccess).getTarget()=vsta_3068
		and target_15.getArgument(2).(PointerFieldAccess).getTarget().getName()="band"
		and target_15.getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="channel"
		and target_15.getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phy_ctxt"
		and target_15.getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvmvif_3073)
}

predicate func_16(Variable vmvm_3072) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="status"
		and target_16.getQualifier().(VariableAccess).getTarget()=vmvm_3072)
}

predicate func_17(Variable vmvmvif_3073) {
	exists(PointerFieldAccess target_17 |
		target_17.getTarget().getName()="phy_ctxt"
		and target_17.getQualifier().(VariableAccess).getTarget()=vmvmvif_3073)
}

from Function func, Parameter vvif_3067, Parameter vsta_3068, Parameter vold_state_3069, Parameter vnew_state_3070, Variable vmvm_3072, Variable vmvmvif_3073, Variable vret_3075, Variable v__ret_warn_on_3218
where
not func_2(vsta_3068, vmvmvif_3073)
and not func_5(vvif_3067, vsta_3068, vold_state_3069, vnew_state_3070, vmvm_3072, vmvmvif_3073)
and func_7(vvif_3067, vsta_3068, vmvm_3072)
and func_8(vvif_3067, vold_state_3069, vnew_state_3070, vmvm_3072)
and func_10(vvif_3067, vold_state_3069, vnew_state_3070, vmvm_3072, vret_3075)
and func_11(vold_state_3069, vnew_state_3070, vret_3075)
and func_12(vvif_3067, vmvm_3072, vmvmvif_3073)
and vvif_3067.getType().hasName("ieee80211_vif *")
and func_14(vvif_3067, vmvm_3072)
and vsta_3068.getType().hasName("ieee80211_sta *")
and func_15(vsta_3068, vmvm_3072, vmvmvif_3073)
and vold_state_3069.getType().hasName("ieee80211_sta_state")
and vnew_state_3070.getType().hasName("ieee80211_sta_state")
and vmvm_3072.getType().hasName("iwl_mvm *")
and func_16(vmvm_3072)
and vmvmvif_3073.getType().hasName("iwl_mvm_vif *")
and func_17(vmvmvif_3073)
and vret_3075.getType().hasName("int")
and v__ret_warn_on_3218.getType().hasName("int")
and vvif_3067.getParentScope+() = func
and vsta_3068.getParentScope+() = func
and vold_state_3069.getParentScope+() = func
and vnew_state_3070.getParentScope+() = func
and vmvm_3072.getParentScope+() = func
and vmvmvif_3073.getParentScope+() = func
and vret_3075.getParentScope+() = func
and v__ret_warn_on_3218.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
