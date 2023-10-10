/**
 * @name linux-c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6-llcp_sock_bind
 * @id cpp/linux/c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6/llcp-sock-bind
 * @description linux-c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6-llcp_sock_bind CVE-2021-23134
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vllcp_sock_62) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="local"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_62
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="service_name"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_62)
}

predicate func_2(Variable vllcp_sock_62) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="local"
		and target_2.getQualifier().(VariableAccess).getTarget()=vllcp_sock_62)
}

from Function func, Variable vllcp_sock_62
where
not func_0(vllcp_sock_62)
and vllcp_sock_62.getType().hasName("nfc_llcp_sock *")
and func_2(vllcp_sock_62)
and vllcp_sock_62.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
