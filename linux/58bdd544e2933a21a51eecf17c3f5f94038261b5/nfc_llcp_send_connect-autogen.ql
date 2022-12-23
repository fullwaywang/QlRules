/**
 * @name linux-58bdd544e2933a21a51eecf17c3f5f94038261b5-nfc_llcp_send_connect
 * @id cpp/linux/58bdd544e2933a21a51eecf17c3f5f94038261b5/nfc_llcp_send_connect
 * @description linux-58bdd544e2933a21a51eecf17c3f5f94038261b5-nfc_llcp_send_connect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsock_400, Variable vservice_name_tlv_404, Variable verr_407) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vservice_name_tlv_404
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_407
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="service_name"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_400
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_3(Variable vmiux_tlv_405, Variable verr_407, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmiux_tlv_405
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_407
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3))
}

predicate func_6(Variable vrw_tlv_406, Variable verr_407, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vrw_tlv_406
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_407
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_6.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_6))
}

predicate func_9(Parameter vsock_400, Variable vservice_name_tlv_404, Variable vservice_name_tlv_length_404) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vservice_name_tlv_404
		and target_9.getRValue().(FunctionCall).getTarget().hasName("nfc_llcp_build_tlv")
		and target_9.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="6"
		and target_9.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="service_name"
		and target_9.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_400
		and target_9.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="service_name_len"
		and target_9.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_400
		and target_9.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vservice_name_tlv_length_404)
}

predicate func_10(Variable vmiux_tlv_405, Variable vmiux_tlv_length_405, Variable vmiux_409) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vmiux_tlv_405
		and target_10.getRValue().(FunctionCall).getTarget().hasName("nfc_llcp_build_tlv")
		and target_10.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_10.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmiux_409
		and target_10.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_10.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmiux_tlv_length_405)
}

predicate func_11(Variable vrw_tlv_406, Variable vrw_tlv_length_406, Variable vrw_406) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vrw_tlv_406
		and target_11.getRValue().(FunctionCall).getTarget().hasName("nfc_llcp_build_tlv")
		and target_11.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_11.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrw_406
		and target_11.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrw_tlv_length_406)
}

from Function func, Parameter vsock_400, Variable vservice_name_tlv_404, Variable vservice_name_tlv_length_404, Variable vmiux_tlv_405, Variable vmiux_tlv_length_405, Variable vrw_tlv_406, Variable vrw_tlv_length_406, Variable vrw_406, Variable verr_407, Variable vmiux_409
where
not func_0(vsock_400, vservice_name_tlv_404, verr_407)
and not func_3(vmiux_tlv_405, verr_407, func)
and not func_6(vrw_tlv_406, verr_407, func)
and vsock_400.getType().hasName("nfc_llcp_sock *")
and vservice_name_tlv_404.getType().hasName("u8 *")
and func_9(vsock_400, vservice_name_tlv_404, vservice_name_tlv_length_404)
and vservice_name_tlv_length_404.getType().hasName("u8")
and vmiux_tlv_405.getType().hasName("u8 *")
and func_10(vmiux_tlv_405, vmiux_tlv_length_405, vmiux_409)
and vmiux_tlv_length_405.getType().hasName("u8")
and vrw_tlv_406.getType().hasName("u8 *")
and func_11(vrw_tlv_406, vrw_tlv_length_406, vrw_406)
and vrw_tlv_length_406.getType().hasName("u8")
and vrw_406.getType().hasName("u8")
and verr_407.getType().hasName("int")
and vmiux_409.getType().hasName("__be16")
and vsock_400.getParentScope+() = func
and vservice_name_tlv_404.getParentScope+() = func
and vservice_name_tlv_length_404.getParentScope+() = func
and vmiux_tlv_405.getParentScope+() = func
and vmiux_tlv_length_405.getParentScope+() = func
and vrw_tlv_406.getParentScope+() = func
and vrw_tlv_length_406.getParentScope+() = func
and vrw_406.getParentScope+() = func
and verr_407.getParentScope+() = func
and vmiux_409.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
