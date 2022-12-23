/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_attach_fds
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/unix_attach_fds
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_attach_fds 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vscm_1533) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="user"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="fp"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vscm_1533)
}

predicate func_1(Parameter vscm_1533) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="fp"
		and target_1.getQualifier().(VariableAccess).getTarget()=vscm_1533)
}

from Function func, Parameter vscm_1533
where
not func_0(vscm_1533)
and vscm_1533.getType().hasName("scm_cookie *")
and func_1(vscm_1533)
and vscm_1533.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
