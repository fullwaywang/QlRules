/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_domain
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-discover-domain
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_discover_domain 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vport_444, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_probe_devices")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_444
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Variable vport_444) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="port_dev"
		and target_1.getQualifier().(VariableAccess).getTarget()=vport_444)
}

from Function func, Variable vport_444
where
not func_0(vport_444, func)
and vport_444.getType().hasName("asd_sas_port *")
and func_1(vport_444)
and vport_444.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
