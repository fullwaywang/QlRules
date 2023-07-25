/**
 * @name wireshark-3e319db1107b08fc3be804b6d449143ec9aa0dec-dissect_pvfs2_getconfig_response
 * @id cpp/wireshark/3e319db1107b08fc3be804b6d449143ec9aa0dec/dissect-pvfs2-getconfig-response
 * @description wireshark-3e319db1107b08fc3be804b6d449143ec9aa0dec-epan/dissectors/packet-pvfs2.c-dissect_pvfs2_getconfig_response CVE-2018-19624
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voffset_2289, Variable vptr_2295, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vptr_2295
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getTarget()=voffset_2289
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter voffset_2289, Variable vptr_2295, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_2295
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ptr")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_2289
}

predicate func_2(Parameter voffset_2289, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_captured_length_remaining")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_2289
}

predicate func_3(Variable vptr_2295, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_2295
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_2295
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
}

from Function func, Parameter voffset_2289, Variable vptr_2295, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3
where
not func_0(voffset_2289, vptr_2295, target_1, target_2, target_3, func)
and func_1(voffset_2289, vptr_2295, target_1)
and func_2(voffset_2289, target_2)
and func_3(vptr_2295, target_3)
and voffset_2289.getType().hasName("int")
and vptr_2295.getType().hasName("const char *")
and voffset_2289.getParentScope+() = func
and vptr_2295.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
