/**
 * @name linux-7574fcdbdcb335763b6b322f6928dc0fd5730451-llcp_sock_connect
 * @id cpp/linux/7574fcdbdcb335763b6b322f6928dc0fd5730451/llcp_sock_connect
 * @description linux-7574fcdbdcb335763b6b322f6928dc0fd5730451-llcp_sock_connect CVE-2020-25672
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vllcp_sock_653, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="service_name"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_653
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_0))
}

predicate func_1(Variable vllcp_sock_653, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="service_name"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vllcp_sock_653
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(41)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(41).getFollowingStmt()=target_1))
}

predicate func_2(Variable vllcp_sock_653) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("nfc_llcp_send_connect")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vllcp_sock_653)
}

from Function func, Variable vllcp_sock_653
where
not func_0(vllcp_sock_653, func)
and not func_1(vllcp_sock_653, func)
and vllcp_sock_653.getType().hasName("nfc_llcp_sock *")
and func_2(vllcp_sock_653)
and vllcp_sock_653.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
