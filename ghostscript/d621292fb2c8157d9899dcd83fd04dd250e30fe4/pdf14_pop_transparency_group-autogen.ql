/**
 * @name ghostscript-d621292fb2c8157d9899dcd83fd04dd250e30fe4-pdf14_pop_transparency_group
 * @id cpp/ghostscript/d621292fb2c8157d9899dcd83fd04dd250e30fe4/pdf14-pop-transparency-group
 * @description ghostscript-d621292fb2c8157d9899dcd83fd04dd250e30fe4-base/gdevp14.c-pdf14_pop_transparency_group CVE-2016-10218
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnos_1052, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnos_1052
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnos_1052, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_components"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent_color_info_procs"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnos_1052
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="num_spots"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnos_1052
}

from Function func, Variable vnos_1052, ExprStmt target_1
where
not func_0(vnos_1052, target_1, func)
and func_1(vnos_1052, target_1)
and vnos_1052.getType().hasName("pdf14_buf *")
and vnos_1052.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
