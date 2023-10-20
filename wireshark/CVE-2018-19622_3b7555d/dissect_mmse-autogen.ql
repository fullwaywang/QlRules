/**
 * @name wireshark-3b7555d32d11862f0e500ec466ad6bfe54190076-dissect_mmse
 * @id cpp/wireshark/3b7555d32d11862f0e500ec466ad6bfe54190076/dissect-mmse
 * @description wireshark-3b7555d32d11862f0e500ec466ad6bfe54190076-epan/dissectors/packet-mmse.c-dissect_mmse CVE-2018-19622
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("guint")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1))
}

predicate func_2(Variable voffset_704, ExprStmt target_4) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_704
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("guint")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Offset isn't increasing"
		and target_4.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable voffset_704) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("guint")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=voffset_704)
}

predicate func_4(Variable voffset_704, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_704
}

from Function func, Variable voffset_704, ExprStmt target_4
where
not func_1(func)
and not func_2(voffset_704, target_4)
and not func_3(voffset_704)
and func_4(voffset_704, target_4)
and voffset_704.getType().hasName("guint")
and voffset_704.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
