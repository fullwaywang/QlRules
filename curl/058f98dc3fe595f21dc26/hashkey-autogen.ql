/**
 * @name curl-058f98dc3fe595f21dc26-hashkey
 * @id cpp/curl/058f98dc3fe595f21dc26/hashkey
 * @description curl-058f98dc3fe595f21dc26-hashkey CVE-2022-27775
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="%ld%s"
		and not target_0.getValue()="%u/%ld/%s"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vconn_135) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="scope_id"
		and target_1.getQualifier().(VariableAccess).getTarget()=vconn_135)
}

predicate func_2(Parameter vconn_135) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="host"
		and target_2.getQualifier().(VariableAccess).getTarget()=vconn_135)
}

from Function func, Parameter vconn_135
where
func_0(func)
and not func_1(vconn_135)
and vconn_135.getType().hasName("connectdata *")
and func_2(vconn_135)
and vconn_135.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
