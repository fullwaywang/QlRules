/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_revalidate_domain
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-revalidate-domain
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_revalidate_domain function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vport_501, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sas_destruct_devices")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_501
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Variable vport_501, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sas_destruct_ports")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_501
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1))
}

predicate func_2(Variable vport_501, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("sas_probe_devices")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_501
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2))
}

predicate func_3(Variable vport_501) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="id"
		and target_3.getQualifier().(VariableAccess).getTarget()=vport_501)
}

from Function func, Variable vport_501
where
not func_0(vport_501, func)
and not func_1(vport_501, func)
and not func_2(vport_501, func)
and vport_501.getType().hasName("asd_sas_port *")
and func_3(vport_501)
and vport_501.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
