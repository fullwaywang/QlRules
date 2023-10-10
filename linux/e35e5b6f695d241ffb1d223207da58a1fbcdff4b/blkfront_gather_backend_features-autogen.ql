/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkfront_gather_backend_features
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/blkfront-gather-backend-features
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkfront_gather_backend_features CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinfo_2243, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="feature_persistent"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2243
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bounce"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2243
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinfo_2243) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="xbdev"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinfo_2243)
}

from Function func, Parameter vinfo_2243
where
not func_0(vinfo_2243, func)
and vinfo_2243.getType().hasName("blkfront_info *")
and func_1(vinfo_2243)
and vinfo_2243.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
