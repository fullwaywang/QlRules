/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_unregister_dev
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-unregister-dev
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_unregister_dev function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_373) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_discover_event")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="port"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_373
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_and_set_bit")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_373)
}

from Function func, Parameter vdev_373
where
func_0(vdev_373)
and vdev_373.getType().hasName("domain_device *")
and vdev_373.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
