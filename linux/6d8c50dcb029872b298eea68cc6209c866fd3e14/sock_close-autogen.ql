/**
 * @name linux-6d8c50dcb029872b298eea68cc6209c866fd3e14-sock_close
 * @id cpp/linux/6d8c50dcb029872b298eea68cc6209c866fd3e14/sock_close
 * @description linux-6d8c50dcb029872b298eea68cc6209c866fd3e14-sock_close 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1172) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sock_release")
		and not target_0.getTarget().hasName("__sock_release")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("SOCKET_I")
		and target_0.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_1172)
}

predicate func_2(Parameter vinode_1172) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("SOCKET_I")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vinode_1172)
}

from Function func, Parameter vinode_1172
where
func_0(vinode_1172)
and vinode_1172.getType().hasName("inode *")
and func_2(vinode_1172)
and vinode_1172.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
