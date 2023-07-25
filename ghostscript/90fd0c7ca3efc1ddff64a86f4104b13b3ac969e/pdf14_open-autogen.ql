/**
 * @name ghostscript-90fd0c7ca3efc1ddff64a86f4104b13b3ac969e-pdf14_open
 * @id cpp/ghostscript/90fd0c7ca3efc1ddff64a86f4104b13b3ac969e/pdf14-open
 * @description ghostscript-90fd0c7ca3efc1ddff64a86f4104b13b3ac969e-base/gdevp14.c-pdf14_open CVE-2016-10217
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpdev_1663, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_1663
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpdev_1663, Variable vrect_1664, Parameter vdev_1661, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_1663
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pdf14_ctx_new")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrect_1664
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="num_components"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="color_info"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1661
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="polarity"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="color_info"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_1663
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdev_1661
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vpdev_1663, Variable vrect_1664, Parameter vdev_1661, ExprStmt target_1
where
not func_0(vpdev_1663, target_1, func)
and func_1(vpdev_1663, vrect_1664, vdev_1661, func, target_1)
and vpdev_1663.getType().hasName("pdf14_device *")
and vrect_1664.getType().hasName("gs_int_rect")
and vdev_1661.getType().hasName("gx_device *")
and vpdev_1663.(LocalVariable).getFunction() = func
and vrect_1664.(LocalVariable).getFunction() = func
and vdev_1661.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
