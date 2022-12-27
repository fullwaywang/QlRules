/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-init_block
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/init-block
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-init_block CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_0) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="last_lit"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_0)
}

from Function func, Parameter vs_0
where
func_0(vs_0)
and vs_0.getType().hasName("deflate_state *")
and vs_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
