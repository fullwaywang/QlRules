/**
 * @name linux-28ebeb8db77035e058a510ce9bd17c2b9a009dba-usbtest_disconnect
 * @id cpp/linux/28ebeb8db77035e058a510ce9bd17c2b9a009dba/usbtest-disconnect
 * @description linux-28ebeb8db77035e058a510ce9bd17c2b9a009dba-usbtest_disconnect 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_2872, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_2872
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

from Function func, Variable vdev_2872
where
not func_0(vdev_2872, func)
and vdev_2872.getType().hasName("usbtest_dev *")
and vdev_2872.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
