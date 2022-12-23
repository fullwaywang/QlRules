/**
 * @name linux-ad5d07f4a9cd671233ae20983848874731102c08-netlbl_cipsov4_list
 * @id cpp/linux/ad5d07f4a9cd671233ae20983848874731102c08/netlbl_cipsov4_list
 * @description linux-ad5d07f4a9cd671233ae20983848874731102c08-netlbl_cipsov4_list 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdoi_def_457, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("cipso_v4_doi_putdef")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdoi_def_457
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_0))
}

predicate func_3(Variable vdoi_def_457) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="map"
		and target_3.getQualifier().(VariableAccess).getTarget()=vdoi_def_457)
}

from Function func, Variable vnlsze_mult_452, Variable vdoi_def_457
where
not func_0(vdoi_def_457, func)
and vnlsze_mult_452.getType().hasName("u32")
and vdoi_def_457.getType().hasName("cipso_v4_doi *")
and func_3(vdoi_def_457)
and vnlsze_mult_452.getParentScope+() = func
and vdoi_def_457.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
