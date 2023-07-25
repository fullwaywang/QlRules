/**
 * @name ghostscript-c432131c3fdb2143e148e8ba88555f7f7a63b25e-gdev_x_open
 * @id cpp/ghostscript/c432131c3fdb2143e148e8ba88555f7f7a63b25e/gdev-x-open
 * @description ghostscript-c432131c3fdb2143e148e8ba88555f7f7a63b25e-devices/gdevxini.c-gdev_x_open CVE-2018-16540
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="set"
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("xv_")
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="set"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("xv_")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0))
}

predicate func_1(Variable vx_error_handler, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="orighandler"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_error_handler
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("XSetErrorHandler")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vx_error_handler, ExprStmt target_1
where
not func_0(func)
and func_1(vx_error_handler, func, target_1)
and vx_error_handler.getType().hasName("xv_")
and not vx_error_handler.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
