/**
 * @name gnutls-ce37f9eb265dbe9b6d597f5767449e8ee95848e2-find_signer
 * @id cpp/gnutls/ce37f9eb265dbe9b6d597f5767449e8ee95848e2/find-signer
 * @description gnutls-ce37f9eb265dbe9b6d597f5767449e8ee95848e2-find_signer CVE-2022-2509
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v__func__) {
	exists(Literal target_0 |
		target_0.getValue()="1334"
		and not target_0.getValue()="1335"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pkcs7.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_1(Variable v__func__) {
	exists(Literal target_1 |
		target_1.getValue()="1342"
		and not target_1.getValue()="1343"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pkcs7.c"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_2(Variable v__func__) {
	exists(Literal target_2 |
		target_2.getValue()="1352"
		and not target_2.getValue()="1353"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pkcs7.c"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_3(Variable v__func__) {
	exists(Literal target_3 |
		target_3.getValue()="1358"
		and not target_3.getValue()="1359"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_gnutls_log")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="3"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ASSERT: %s[%s]:%d\n"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pkcs7.c"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__)
}

predicate func_4(Variable vsigner_1246, Variable vprev_1312) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vprev_1312
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vprev_1312
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsigner_1246
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gnutls_x509_crt_deinit")
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprev_1312)
}

predicate func_6(Variable vsigner_1246, Variable vprev_1312) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vprev_1312
		and target_6.getAnOperand().(VariableAccess).getTarget()=vsigner_1246
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprev_1312
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gnutls_x509_crt_deinit")
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprev_1312)
}

predicate func_7(Variable vissuer_1245, Variable vprev_1312) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vprev_1312
		and target_7.getRValue().(VariableAccess).getTarget()=vissuer_1245)
}

from Function func, Variable vissuer_1245, Variable vsigner_1246, Variable v__func__, Variable vprev_1312
where
func_0(v__func__)
and func_1(v__func__)
and func_2(v__func__)
and func_3(v__func__)
and not func_4(vsigner_1246, vprev_1312)
and vsigner_1246.getType().hasName("gnutls_x509_crt_t")
and func_6(vsigner_1246, vprev_1312)
and v__func__.getType().hasName("const char[12]")
and vprev_1312.getType().hasName("gnutls_x509_crt_t")
and func_7(vissuer_1245, vprev_1312)
and vissuer_1245.getParentScope+() = func
and vsigner_1246.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vprev_1312.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
