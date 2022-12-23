/**
 * @name linux-c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6-llcp_sock_connect
 * @id cpp/linux/c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6/llcp-sock-connect
 * @description linux-c61760e6940dd4039a7f5e84a6afc9cdbf4d82b6-llcp_sock_connect CVE-2021-23134
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vllcp_sock_653) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="local"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_653
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ssap"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_653
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="255")
}

predicate func_2(Variable vllcp_sock_653) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="local"
		and target_2.getQualifier().(VariableAccess).getTarget()=vllcp_sock_653)
}

from Function func, Variable vllcp_sock_653
where
not func_0(vllcp_sock_653)
and vllcp_sock_653.getType().hasName("nfc_llcp_sock *")
and func_2(vllcp_sock_653)
and vllcp_sock_653.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
