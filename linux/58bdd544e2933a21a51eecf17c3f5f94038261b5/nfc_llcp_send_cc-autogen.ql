/**
 * @name linux-58bdd544e2933a21a51eecf17c3f5f94038261b5-nfc_llcp_send_cc
 * @id cpp/linux/58bdd544e2933a21a51eecf17c3f5f94038261b5/nfc_llcp_send_cc
 * @description linux-58bdd544e2933a21a51eecf17c3f5f94038261b5-nfc_llcp_send_cc 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vmiux_tlv_468, Variable verr_470, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmiux_tlv_468
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_470
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_3(Variable vrw_tlv_469, Variable verr_470, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vrw_tlv_469
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_470
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_3))
}

predicate func_6(Variable vmiux_tlv_468, Variable vmiux_tlv_length_468, Variable vmiux_472) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vmiux_tlv_468
		and target_6.getRValue().(FunctionCall).getTarget().hasName("nfc_llcp_build_tlv")
		and target_6.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_6.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmiux_472
		and target_6.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_6.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmiux_tlv_length_468)
}

predicate func_7(Variable vrw_tlv_469, Variable vrw_tlv_length_469, Variable vrw_469) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vrw_tlv_469
		and target_7.getRValue().(FunctionCall).getTarget().hasName("nfc_llcp_build_tlv")
		and target_7.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_7.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrw_469
		and target_7.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_7.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrw_tlv_length_469)
}

from Function func, Variable vmiux_tlv_468, Variable vmiux_tlv_length_468, Variable vrw_tlv_469, Variable vrw_tlv_length_469, Variable vrw_469, Variable verr_470, Variable vmiux_472
where
not func_0(vmiux_tlv_468, verr_470, func)
and not func_3(vrw_tlv_469, verr_470, func)
and vmiux_tlv_468.getType().hasName("u8 *")
and func_6(vmiux_tlv_468, vmiux_tlv_length_468, vmiux_472)
and vmiux_tlv_length_468.getType().hasName("u8")
and vrw_tlv_469.getType().hasName("u8 *")
and func_7(vrw_tlv_469, vrw_tlv_length_469, vrw_469)
and vrw_tlv_length_469.getType().hasName("u8")
and vrw_469.getType().hasName("u8")
and verr_470.getType().hasName("int")
and vmiux_472.getType().hasName("__be16")
and vmiux_tlv_468.getParentScope+() = func
and vmiux_tlv_length_468.getParentScope+() = func
and vrw_tlv_469.getParentScope+() = func
and vrw_tlv_length_469.getParentScope+() = func
and vrw_469.getParentScope+() = func
and verr_470.getParentScope+() = func
and vmiux_472.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
