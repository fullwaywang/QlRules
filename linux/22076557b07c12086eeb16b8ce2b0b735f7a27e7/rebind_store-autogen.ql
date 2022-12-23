/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-rebind_store
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/rebind_store
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-rebind_store 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vbid_223, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("put_busid_priv")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbid_223
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vbid_223) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="status"
		and target_1.getQualifier().(VariableAccess).getTarget()=vbid_223)
}

from Function func, Variable vbid_223
where
not func_0(vbid_223, func)
and vbid_223.getType().hasName("bus_id_priv *")
and func_1(vbid_223)
and vbid_223.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
