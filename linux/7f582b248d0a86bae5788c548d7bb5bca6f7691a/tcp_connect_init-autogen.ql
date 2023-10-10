/**
 * @name linux-7f582b248d0a86bae5788c548d7bb5bca6f7691a-tcp_connect_init
 * @id cpp/linux/7f582b248d0a86bae5788c548d7bb5bca6f7691a/tcp_connect_init
 * @description linux-7f582b248d0a86bae5788c548d7bb5bca6f7691a-tcp_connect_init 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsk_3287, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("tcp_write_queue_purge")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_3287
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsk_3287) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sock_reset_flag")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vsk_3287)
}

from Function func, Parameter vsk_3287
where
not func_0(vsk_3287, func)
and vsk_3287.getType().hasName("sock *")
and func_1(vsk_3287)
and vsk_3287.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
