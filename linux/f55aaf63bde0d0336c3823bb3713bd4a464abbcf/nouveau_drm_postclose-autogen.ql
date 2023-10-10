/**
 * @name linux-f55aaf63bde0d0336c3823bb3713bd4a464abbcf-nouveau_drm_postclose
 * @id cpp/linux/f55aaf63bde0d0336c3823bb3713bd4a464abbcf/nouveau-drm-postclose
 * @description linux-f55aaf63bde0d0336c3823bb3713bd4a464abbcf-nouveau_drm_postclose CVE-2020-27820
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Parameter vdev_1111, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("drm_dev_enter")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_1111
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("drm_dev_exit")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vdev_1111) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("nouveau_drm")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdev_1111)
}

from Function func, Parameter vdev_1111
where
not func_0(func)
and not func_1(vdev_1111, func)
and not func_2(func)
and vdev_1111.getType().hasName("drm_device *")
and func_3(vdev_1111)
and vdev_1111.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
