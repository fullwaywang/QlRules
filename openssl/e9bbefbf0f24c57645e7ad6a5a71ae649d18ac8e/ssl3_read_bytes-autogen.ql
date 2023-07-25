/**
 * @name openssl-e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e-ssl3_read_bytes
 * @id cpp/openssl/e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e/ssl3-read-bytes
 * @description openssl-e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e-ssl/s3_pkt.c-ssl3_read_bytes CVE-2019-1559
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1166, EqualityOperation target_1, ExprStmt target_2, BitwiseAndExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1166
		and target_0.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="12293"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(Literal).getValue()="2"
}

predicate func_2(Parameter vs_1166, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1166
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1166
}

predicate func_3(Parameter vs_1166, BitwiseAndExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="shutdown"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1166
		and target_3.getRightOperand().(Literal).getValue()="1"
}

from Function func, Parameter vs_1166, EqualityOperation target_1, ExprStmt target_2, BitwiseAndExpr target_3
where
not func_0(vs_1166, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vs_1166, target_2)
and func_3(vs_1166, target_3)
and vs_1166.getType().hasName("SSL *")
and vs_1166.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
