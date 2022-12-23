/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_end_dev
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-discover-end-dev
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_end_dev function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_290, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_discover_event")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="port"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_290
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vdev_290
where
func_0(vdev_290, func)
and vdev_290.getType().hasName("domain_device *")
and vdev_290.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
