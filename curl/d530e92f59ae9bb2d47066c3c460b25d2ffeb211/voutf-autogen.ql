/**
 * @name curl-d530e92f59ae9bb2d47066c3c460b25d2ffeb211-voutf
 * @id cpp/curl/d530e92f59ae9bb2d47066c3c460b25d2ffeb211/voutf
 * @description curl-d530e92f59ae9bb2d47066c3c460b25d2ffeb211-src/tool_msgs.c-voutf CVE-2018-16842
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcut_57, ExprStmt target_2) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vcut_57
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(AssignSubExpr).getRValue() = target_0
		and target_2.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcut_57, VariableAccess target_1) {
		target_1.getTarget()=vcut_57
		and target_1.getParent().(AssignSubExpr).getRValue() = target_1
}

predicate func_2(Variable vcut_57, ExprStmt target_2) {
		target_2.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcut_57
		and target_2.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vcut_57, VariableAccess target_1, ExprStmt target_2
where
not func_0(vcut_57, target_2)
and func_1(vcut_57, target_1)
and func_2(vcut_57, target_2)
and vcut_57.getType().hasName("size_t")
and vcut_57.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
