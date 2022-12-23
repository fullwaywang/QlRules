/**
 * @name linux-07f12b26e21ab359261bf75cfcb424fdc7daeb6d-sit_init_net
 * @id cpp/linux/07f12b26e21ab359261bf75cfcb424fdc7daeb6d/sit_init_net
 * @description linux-07f12b26e21ab359261bf75cfcb424fdc7daeb6d-sit_init_net 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsitn_1836, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("free_netdev")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fb_tunnel_dev"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsitn_1836
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_0))
}

predicate func_1(Variable vsitn_1836) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="fb_tunnel_dev"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsitn_1836)
}

from Function func, Variable vsitn_1836
where
not func_0(vsitn_1836, func)
and vsitn_1836.getType().hasName("sit_net *")
and func_1(vsitn_1836)
and vsitn_1836.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
