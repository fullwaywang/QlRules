/**
 * @name linux-8e2d61e0aed2b7c4ecb35844fe07e0b2b762dee4-sctp_exit
 * @id cpp/linux/8e2d61e0aed2b7c4ecb35844fe07e0b2b762dee4/sctp_exit
 * @description linux-8e2d61e0aed2b7c4ecb35844fe07e0b2b762dee4-sctp_exit 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsctp_net_ops) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vsctp_net_ops)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("unregister_pernet_subsys")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("pernet_operations")
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

from Function func, Variable vsctp_net_ops
where
func_0(vsctp_net_ops)
and not func_1(func)
and not vsctp_net_ops.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
