/**
 * @name openssl-2a40b7bc7b94dd7de897a74571e7024f0cf0d63b-test_alt_chains_cert_forgery
 * @id cpp/openssl/2a40b7bc7b94dd7de897a74571e7024f0cf0d63b/test-alt-chains-cert-forgery
 * @description openssl-2a40b7bc7b94dd7de897a74571e7024f0cf0d63b-test_alt_chains_cert_forgery CVE-2021-3450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vsctx_112, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("X509_STORE_CTX_cleanup")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_2))
}

predicate func_3(Variable vstore_113, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("X509_STORE_set_flags")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstore_113
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_3))
}

predicate func_4(Variable vx_109, Variable vuntrusted_110, Variable vsctx_112, Variable vstore_113, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_init")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstore_113
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx_109
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuntrusted_110
		and target_4.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_4))
}

predicate func_5(Variable vi_108, Variable vsctx_112, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_108
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("X509_verify_cert")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_5))
}

predicate func_6(Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition() instanceof LogicalAndExpr
		and target_6.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_6))
}

predicate func_8(Variable vret_107, Variable vi_108, Variable vsctx_112) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_107
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_108
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_get_error")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="24")
}

predicate func_9(Variable vi_108, Variable vsctx_112) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vi_108
		and target_9.getRValue().(FunctionCall).getTarget().hasName("X509_verify_cert")
		and target_9.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112)
}

predicate func_10(Variable vx_109, Variable vuntrusted_110, Variable vsctx_112, Variable vstore_113) {
	exists(NotExpr target_10 |
		target_10.getOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_init")
		and target_10.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx_112
		and target_10.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstore_113
		and target_10.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vx_109
		and target_10.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuntrusted_110
		and target_10.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

from Function func, Variable vret_107, Variable vi_108, Variable vx_109, Variable vuntrusted_110, Variable vsctx_112, Variable vstore_113
where
not func_2(vsctx_112, func)
and not func_3(vstore_113, func)
and not func_4(vx_109, vuntrusted_110, vsctx_112, vstore_113, func)
and not func_5(vi_108, vsctx_112, func)
and not func_6(func)
and func_8(vret_107, vi_108, vsctx_112)
and vret_107.getType().hasName("int")
and vi_108.getType().hasName("int")
and func_9(vi_108, vsctx_112)
and vx_109.getType().hasName("X509 *")
and func_10(vx_109, vuntrusted_110, vsctx_112, vstore_113)
and vuntrusted_110.getType().hasName("stack_st_X509 *")
and vsctx_112.getType().hasName("X509_STORE_CTX *")
and vstore_113.getType().hasName("X509_STORE *")
and vret_107.getParentScope+() = func
and vi_108.getParentScope+() = func
and vx_109.getParentScope+() = func
and vuntrusted_110.getParentScope+() = func
and vsctx_112.getParentScope+() = func
and vstore_113.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
