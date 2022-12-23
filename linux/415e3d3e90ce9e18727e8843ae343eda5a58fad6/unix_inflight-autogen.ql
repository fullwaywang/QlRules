/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_inflight
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/unix_inflight
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_inflight 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vfp_119) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="f_cred"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_119)
}

from Function func, Parameter vfp_119
where
func_1(vfp_119)
and vfp_119.getType().hasName("file *")
and vfp_119.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
