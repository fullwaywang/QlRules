/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_evtchn_cpu_prepare
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/xen-evtchn-cpu-prepare
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_evtchn_cpu_prepare 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcpu_1834, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xen_cpu_init_eoi")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcpu_1834
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vcpu_1834
where
not func_0(vcpu_1834, func)
and vcpu_1834.getType().hasName("unsigned int")
and vcpu_1834.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
