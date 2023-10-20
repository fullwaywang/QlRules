/**
 * @name wireshark-73c5fff899f253c44a72657048aec7db6edee571-wg_dissect_data
 * @id cpp/wireshark/73c5fff899f253c44a72657048aec7db6edee571/wg-dissect-data
 * @description wireshark-73c5fff899f253c44a72657048aec7db6edee571-epan/dissectors/packet-wireguard.c-wg_dissect_data CVE-2020-9429
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwg_pinfo_1527, ExprStmt target_2, ExprStmt target_3) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vwg_pinfo_1527
		and target_0.getThen().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1527
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vwg_pinfo_1527, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="session"
		and target_1.getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1527
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

predicate func_2(Parameter vwg_pinfo_1527, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="receiver_is_initiator"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1527
}

predicate func_3(Parameter vwg_pinfo_1527, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("wg_dissect_decrypted_packet")
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vwg_pinfo_1527
		and target_3.getExpr().(FunctionCall).getArgument(5).(SubExpr).getRightOperand().(Literal).getValue()="16"
}

from Function func, Parameter vwg_pinfo_1527, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vwg_pinfo_1527, target_2, target_3)
and func_1(vwg_pinfo_1527, target_1)
and func_2(vwg_pinfo_1527, target_2)
and func_3(vwg_pinfo_1527, target_3)
and vwg_pinfo_1527.getType().hasName("wg_packet_info_t *")
and vwg_pinfo_1527.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
