/**
 * @name linux-cb66ddd156203daefb8d71158036b27b0e2caf63-rds_tcp_kill_sock
 * @id cpp/linux/cb66ddd156203daefb8d71158036b27b0e2caf63/rds_tcp_kill_sock
 * @description linux-cb66ddd156203daefb8d71158036b27b0e2caf63-rds_tcp_kill_sock 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vc_net_609, Parameter vnet_598) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vnet_598
		and target_0.getAnOperand().(VariableAccess).getTarget()=vc_net_609
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ContinueStmt).toString() = "continue;")
}

predicate func_1(Variable vtc_600) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="t_sock"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtc_600
		and target_1.getParent().(IfStmt).getThen().(ContinueStmt).toString() = "continue;")
}

from Function func, Variable vc_net_609, Variable vtc_600, Parameter vnet_598
where
func_0(vc_net_609, vnet_598)
and func_1(vtc_600)
and vc_net_609.getType().hasName("net *")
and vtc_600.getType().hasName("rds_tcp_connection *")
and vnet_598.getType().hasName("net *")
and vc_net_609.getParentScope+() = func
and vtc_600.getParentScope+() = func
and vnet_598.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
