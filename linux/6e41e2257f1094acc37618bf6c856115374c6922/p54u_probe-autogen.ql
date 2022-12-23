/**
 * @name linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_probe
 * @id cpp/linux/6e41e2257f1094acc37618bf6c856115374c6922/p54u_probe
 * @description linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_992, Variable verr_994) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("p54_free_common")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_992
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_994)
}

predicate func_1(Variable vudev_991, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("usb_get_dev")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vudev_991
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vudev_991, Variable verr_994) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("usb_put_dev")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vudev_991
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_994)
}

from Function func, Variable vudev_991, Variable vdev_992, Variable verr_994
where
func_0(vdev_992, verr_994)
and func_1(vudev_991, func)
and func_2(vudev_991, verr_994)
and vudev_991.getType().hasName("usb_device *")
and vdev_992.getType().hasName("ieee80211_hw *")
and verr_994.getType().hasName("int")
and vudev_991.getParentScope+() = func
and vdev_992.getParentScope+() = func
and verr_994.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
