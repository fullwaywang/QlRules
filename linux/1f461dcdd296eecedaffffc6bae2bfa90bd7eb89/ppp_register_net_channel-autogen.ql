/**
 * @name linux-1f461dcdd296eecedaffffc6bae2bfa90bd7eb89-ppp_register_net_channel
 * @id cpp/linux/1f461dcdd296eecedaffffc6bae2bfa90bd7eb89/ppp_register_net_channel
 * @description linux-1f461dcdd296eecedaffffc6bae2bfa90bd7eb89-ppp_register_net_channel 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2297) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_net")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_2297)
}

from Function func, Parameter vnet_2297
where
not func_0(vnet_2297)
and vnet_2297.getType().hasName("net *")
and vnet_2297.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
