/**
 * @name haproxy-3f0e1ec70173593f4c2b3681b26c04a4ed5fc588-h2_process_demux
 * @id cpp/haproxy/3f0e1ec70173593f4c2b3681b26c04a4ed5fc588/h2-process-demux
 * @description haproxy-3f0e1ec70173593f4c2b3681b26c04a4ed5fc588-src/mux_h2.c-h2_process_demux CVE-2018-10184
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="bufsize"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="tune"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("global")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="bufsize"
		and target_1.getQualifier().(ValueFieldAccess).getTarget().getName()="tune"
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("global")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vh2c_1698, ExprStmt target_4, ExprStmt target_5, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="mfs"
		and target_2.getQualifier().(VariableAccess).getTarget()=vh2c_1698
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_3(Parameter vh2c_1698, NotExpr target_6, ExprStmt target_7, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="mfs"
		and target_3.getQualifier().(VariableAccess).getTarget()=vh2c_1698
		and target_6.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_4(Parameter vh2c_1698, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="st0"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2c_1698
}

predicate func_5(Parameter vh2c_1698, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("h2c_error")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh2c_1698
}

predicate func_6(Parameter vh2c_1698, NotExpr target_6) {
		target_6.getOperand().(FunctionCall).getTarget().hasName("h2_peek_frame_hdr")
		and target_6.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dbuf"
		and target_6.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2c_1698
}

predicate func_7(Parameter vh2c_1698, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("h2c_error")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh2c_1698
}

from Function func, Parameter vh2c_1698, PointerFieldAccess target_2, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5, NotExpr target_6, ExprStmt target_7
where
not func_0(func)
and not func_1(func)
and func_2(vh2c_1698, target_4, target_5, target_2)
and func_3(vh2c_1698, target_6, target_7, target_3)
and func_4(vh2c_1698, target_4)
and func_5(vh2c_1698, target_5)
and func_6(vh2c_1698, target_6)
and func_7(vh2c_1698, target_7)
and vh2c_1698.getType().hasName("h2c *")
and vh2c_1698.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
