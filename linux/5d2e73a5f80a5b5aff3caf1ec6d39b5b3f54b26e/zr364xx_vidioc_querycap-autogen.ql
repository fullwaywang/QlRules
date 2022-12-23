/**
 * @name linux-5d2e73a5f80a5b5aff3caf1ec6d39b5b3f54b26e-zr364xx_vidioc_querycap
 * @id cpp/linux/5d2e73a5f80a5b5aff3caf1ec6d39b5b3f54b26e/zr364xx-vidioc-querycap
 * @description linux-5d2e73a5f80a5b5aff3caf1ec6d39b5b3f54b26e-zr364xx_vidioc_querycap 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcam_703, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="product"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="udev"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcam_703
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcap_701, Variable vcam_703, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("strscpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="card"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_701
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="product"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcam_703
		and target_1.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_1.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="card"
		and target_1.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_701
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vcap_701, Variable vcam_703
where
not func_0(vcam_703, func)
and func_1(vcap_701, vcam_703, func)
and vcap_701.getType().hasName("v4l2_capability *")
and vcam_703.getType().hasName("zr364xx_camera *")
and vcap_701.getParentScope+() = func
and vcam_703.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
