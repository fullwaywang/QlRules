/**
 * @name linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-xfrm_state_fini
 * @id cpp/linux/dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399/xfrm_state_fini
 * @description linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-xfrm_state_fini 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2381) {
	exists(Literal target_0 |
		target_0.getValue()="255"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xfrm_state_flush")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_2381)
}

from Function func, Parameter vnet_2381
where
func_0(vnet_2381)
and vnet_2381.getType().hasName("net *")
and vnet_2381.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
