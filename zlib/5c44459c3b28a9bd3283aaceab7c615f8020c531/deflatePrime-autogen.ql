/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflatePrime
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflatePrime
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflatePrime CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_550) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="sym_buf"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_550)
}

predicate func_2(Variable vs_550) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="d_buf"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_550)
}

from Function func, Variable vs_550
where
not func_0(vs_550)
and func_2(vs_550)
and vs_550.getType().hasName("deflate_state *")
and vs_550.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
