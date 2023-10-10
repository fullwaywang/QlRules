/**
 * @name linux-34e5b01186858b36c4d7c87e1a025071e8e2401f-sctp_sock_migrate
 * @id cpp/linux/34e5b01186858b36c4d7c87e1a025071e8e2401f/sctp_sock_migrate
 * @description linux-34e5b01186858b36c4d7c87e1a025071e8e2401f-sctp_sock_migrate CVE-2021-23133
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnewsp_9354, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sctp_auto_asconf_init")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewsp_9354
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0))
}

predicate func_1(Variable vnewsp_9354) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ep"
		and target_1.getQualifier().(VariableAccess).getTarget()=vnewsp_9354)
}

from Function func, Variable vnewsp_9354
where
not func_0(vnewsp_9354, func)
and vnewsp_9354.getType().hasName("sctp_sock *")
and func_1(vnewsp_9354)
and vnewsp_9354.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
