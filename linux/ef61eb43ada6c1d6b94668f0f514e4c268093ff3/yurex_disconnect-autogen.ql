/**
 * @name linux-ef61eb43ada6c1d6b94668f0f514e4c268093ff3-yurex_disconnect
 * @id cpp/linux/ef61eb43ada6c1d6b94668f0f514e4c268093ff3/yurex_disconnect
 * @description linux-ef61eb43ada6c1d6b94668f0f514e4c268093ff3-yurex_disconnect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_307, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("usb_poison_urb")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="urb"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_307
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinterface_305, Variable vdev_307) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vdev_307
		and target_1.getRValue().(FunctionCall).getTarget().hasName("usb_get_intfdata")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinterface_305)
}

from Function func, Parameter vinterface_305, Variable vdev_307
where
not func_0(vdev_307, func)
and vdev_307.getType().hasName("usb_yurex *")
and func_1(vinterface_305, vdev_307)
and vinterface_305.getParentScope+() = func
and vdev_307.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
