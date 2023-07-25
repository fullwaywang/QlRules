/**
 * @name wireshark-73c5fff899f253c44a72657048aec7db6edee571-wg_dissect_handshake_initiation
 * @id cpp/wireshark/73c5fff899f253c44a72657048aec7db6edee571/wg-dissect-handshake-initiation
 * @description wireshark-73c5fff899f253c44a72657048aec7db6edee571-epan/dissectors/packet-wireguard.c-wg_dissect_handshake_initiation CVE-2020-9429
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwg_pinfo_1364, BlockStmt target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vwg_pinfo_1364
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vwg_pinfo_1364, ExprStmt target_6) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vwg_pinfo_1364
		and target_1.getThen().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
		and target_1.getElse().(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vwg_pinfo_1364, BlockStmt target_4, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="session"
		and target_2.getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vwg_pinfo_1364, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="session"
		and target_3.getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
}

predicate func_4(Parameter vwg_pinfo_1364, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hs"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
}

predicate func_5(Parameter vwg_pinfo_1364, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hs"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
}

predicate func_6(Parameter vwg_pinfo_1364, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="session"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwg_pinfo_1364
}

from Function func, Parameter vwg_pinfo_1364, PointerFieldAccess target_2, PointerFieldAccess target_3, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vwg_pinfo_1364, target_4, target_5)
and not func_1(vwg_pinfo_1364, target_6)
and func_2(vwg_pinfo_1364, target_4, target_2)
and func_3(vwg_pinfo_1364, target_3)
and func_4(vwg_pinfo_1364, target_4)
and func_5(vwg_pinfo_1364, target_5)
and func_6(vwg_pinfo_1364, target_6)
and vwg_pinfo_1364.getType().hasName("wg_packet_info_t *")
and vwg_pinfo_1364.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
