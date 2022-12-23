/**
 * @name linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-xfrm6_tunnel_net_exit
 * @id cpp/linux/dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399/xfrm6_tunnel_net_exit
 * @description linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-xfrm6_tunnel_net_exit 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_342) {
	exists(Literal target_0 |
		target_0.getValue()="255"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xfrm_state_flush")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_342)
}

from Function func, Parameter vnet_342
where
func_0(vnet_342)
and vnet_342.getType().hasName("net *")
and vnet_342.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
