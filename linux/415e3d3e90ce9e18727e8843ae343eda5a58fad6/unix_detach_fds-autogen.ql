/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_detach_fds
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/unix_detach_fds
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_detach_fds 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vscm_1491) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="user"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="fp"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscm_1491)
}

predicate func_1(Parameter vscm_1491) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="fp"
		and target_1.getQualifier().(VariableAccess).getTarget()=vscm_1491)
}

from Function func, Parameter vscm_1491
where
not func_0(vscm_1491)
and vscm_1491.getType().hasName("scm_cookie *")
and func_1(vscm_1491)
and vscm_1491.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
