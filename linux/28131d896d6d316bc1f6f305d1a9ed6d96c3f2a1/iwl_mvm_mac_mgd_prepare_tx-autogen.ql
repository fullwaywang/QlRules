/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_mgd_prepare_tx
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-mac-mgd-prepare-tx
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_mgd_prepare_tx CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvif_3315, Variable vmvm_3318, Variable vmin_duration_3320) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("iwl_mvm_schedule_session_protection")
		and not target_0.getTarget().hasName("iwl_mvm_protect_assoc")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmvm_3318
		and target_0.getArgument(1).(VariableAccess).getTarget()=vvif_3315
		and target_0.getArgument(2).(Literal).getValue()="900"
		and target_0.getArgument(3).(VariableAccess).getTarget()=vmin_duration_3320)
}

predicate func_1(Parameter vinfo_3316, Variable vduration_3319) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="duration"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinfo_3316
		and target_1.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vduration_3319
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="600"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="400"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vinfo_3316, Variable vduration_3319, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand() instanceof PointerFieldAccess
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vduration_3319
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vduration_3319
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="duration"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_3316
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Parameter vvif_3315, Variable vmvm_3318, Variable vduration_3319, Variable vmin_duration_3320, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(FunctionCall).getTarget().hasName("fw_has_capa")
		and target_5.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_5.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fw"
		and target_5.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_3318
		and target_5.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_protect_session")
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_3318
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvif_3315
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vduration_3319
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmin_duration_3320
		and target_5.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="500"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

from Function func, Parameter vvif_3315, Parameter vinfo_3316, Variable vmvm_3318, Variable vduration_3319, Variable vmin_duration_3320
where
func_0(vvif_3315, vmvm_3318, vmin_duration_3320)
and func_1(vinfo_3316, vduration_3319)
and func_2(func)
and func_3(func)
and func_4(vinfo_3316, vduration_3319, func)
and func_5(vvif_3315, vmvm_3318, vduration_3319, vmin_duration_3320, func)
and vvif_3315.getType().hasName("ieee80211_vif *")
and vinfo_3316.getType().hasName("ieee80211_prep_tx_info *")
and vmvm_3318.getType().hasName("iwl_mvm *")
and vduration_3319.getType().hasName("u32")
and vmin_duration_3320.getType().hasName("u32")
and vvif_3315.getParentScope+() = func
and vinfo_3316.getParentScope+() = func
and vmvm_3318.getParentScope+() = func
and vduration_3319.getParentScope+() = func
and vmin_duration_3320.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
