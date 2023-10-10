/**
 * @name linux-c33b1cc62ac05c1dbb1cdafe2eb66da01c76ca8d-llcp_sock_bind
 * @id cpp/linux/c33b1cc62ac05c1dbb1cdafe2eb66da01c76ca8d/llcp_sock_bind
 * @description linux-c33b1cc62ac05c1dbb1cdafe2eb66da01c76ca8d-llcp_sock_bind CVE-2020-25670
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vllcp_sock_62) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("nfc_llcp_local_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="local"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_62
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="service_name"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_62)
}

predicate func_2(Variable vllcp_sock_62) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="service_name"
		and target_2.getQualifier().(VariableAccess).getTarget()=vllcp_sock_62)
}

predicate func_3(Variable vllcp_sock_62) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="ssap"
		and target_3.getQualifier().(VariableAccess).getTarget()=vllcp_sock_62)
}

from Function func, Variable vllcp_sock_62
where
not func_0(vllcp_sock_62)
and vllcp_sock_62.getType().hasName("nfc_llcp_sock *")
and func_2(vllcp_sock_62)
and func_3(vllcp_sock_62)
and vllcp_sock_62.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
