/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-get_grant
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/get-grant
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-get_grant CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1163"
		and not target_0.getValue()="1165"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vinfo_371) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="feature_persistent"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinfo_371)
}

from Function func, Variable vinfo_371
where
func_0(func)
and func_1(vinfo_371)
and vinfo_371.getType().hasName("blkfront_info *")
and vinfo_371.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
