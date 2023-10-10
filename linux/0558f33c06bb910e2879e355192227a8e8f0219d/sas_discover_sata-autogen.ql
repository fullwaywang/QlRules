/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_sata
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-discover-sata
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_sata function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdev_719, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_discover_event")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="port"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_719
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vdev_719
where
func_0(vdev_719, func)
and vdev_719.getType().hasName("domain_device *")
and vdev_719.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
