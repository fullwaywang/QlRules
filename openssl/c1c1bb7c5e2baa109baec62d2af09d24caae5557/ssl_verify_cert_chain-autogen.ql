/**
 * @name openssl-c1c1bb7c5e2baa109baec62d2af09d24caae5557-ssl_verify_cert_chain
 * @id cpp/openssl/c1c1bb7c5e2baa109baec62d2af09d24caae5557/ssl-verify-cert-chain
 * @description openssl-c1c1bb7c5e2baa109baec62d2af09d24caae5557-ssl_verify_cert_chain CVE-2021-4044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_368, Parameter vs_365) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_368
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_368
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="app_verify_callback"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_365
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vi_368, Variable vctx_370, Parameter vs_365) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_368
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="app_verify_callback"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_365
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vctx_370
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="app_verify_arg"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_365
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="app_verify_callback"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_365
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_3(Variable vi_368, Variable vctx_370, Parameter vs_365) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_368
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("X509_verify_cert")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_370
		and target_3.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="app_verify_callback"
		and target_3.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_3.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_365
		and target_3.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

from Function func, Variable vi_368, Variable vctx_370, Parameter vs_365
where
not func_0(vi_368, vs_365)
and func_2(vi_368, vctx_370, vs_365)
and func_3(vi_368, vctx_370, vs_365)
and vi_368.getType().hasName("int")
and vctx_370.getType().hasName("X509_STORE_CTX *")
and vs_365.getType().hasName("SSL *")
and vi_368.getParentScope+() = func
and vctx_370.getParentScope+() = func
and vs_365.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
