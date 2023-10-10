/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_responder_set_bw_v2
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-ftm-responder-set-bw-v2
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_responder_set_bw_v2 CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vchandef_48, Parameter vformat_bw_49, Parameter vctrl_ch_position_50) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("u8")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vformat_bw_49
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vformat_bw_49
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vctrl_ch_position_50
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_mvm_get_ctrl_pos")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchandef_48
		and target_1.getThen().(BlockStmt).getStmt(3).(BreakStmt).toString() = "break;")
}

predicate func_6(Function func) {
	exists(EmptyStmt target_6 |
		target_6.toString() = ";"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vchandef_48) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("iwl_mvm_get_ctrl_pos")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vchandef_48)
}

predicate func_8(Parameter vformat_bw_49) {
	exists(PointerDereferenceExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vformat_bw_49)
}

predicate func_9(Parameter vchandef_48, Parameter vctrl_ch_position_50) {
	exists(PointerDereferenceExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vctrl_ch_position_50
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_mvm_get_ctrl_pos")
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchandef_48)
}

from Function func, Parameter vchandef_48, Parameter vformat_bw_49, Parameter vctrl_ch_position_50
where
not func_1(vchandef_48, vformat_bw_49, vctrl_ch_position_50)
and not func_6(func)
and vchandef_48.getType().hasName("cfg80211_chan_def *")
and func_7(vchandef_48)
and vformat_bw_49.getType().hasName("u8 *")
and func_8(vformat_bw_49)
and vctrl_ch_position_50.getType().hasName("u8 *")
and func_9(vchandef_48, vctrl_ch_position_50)
and vchandef_48.getParentScope+() = func
and vformat_bw_49.getParentScope+() = func
and vctrl_ch_position_50.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
