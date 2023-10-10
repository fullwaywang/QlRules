/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_notinflight
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/unix_notinflight
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-unix_notinflight 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vfp_140) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="f_cred"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_140)
}

from Function func, Parameter vfp_140
where
func_1(vfp_140)
and vfp_140.getType().hasName("file *")
and vfp_140.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
