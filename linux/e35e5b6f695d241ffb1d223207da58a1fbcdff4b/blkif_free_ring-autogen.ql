/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkif_free_ring
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/blkif-free-ring
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkif_free_ring CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_1200) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="feature_persistent"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinfo_1200)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1177"
		and not target_1.getValue()="1179"
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1178"
		and not target_3.getValue()="1180"
		and target_3.getEnclosingFunction() = func)
}

from Function func, Variable vinfo_1200
where
func_0(vinfo_1200)
and func_1(func)
and func_3(func)
and vinfo_1200.getType().hasName("blkfront_info *")
and vinfo_1200.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
