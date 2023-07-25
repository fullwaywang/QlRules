/**
 * @name openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-tls_finish_handshake
 * @id cpp/openssl/f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d/tls-finish-handshake
 * @description openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-tls_finish_handshake CVE-2016-2179
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_273) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dtls1_clear_received_buffer")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_273
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="enc_flags"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl3_enc"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_1(Parameter vs_273) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="next_handshake_write_seq"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_273
		and target_1.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vs_273
where
not func_0(vs_273)
and vs_273.getType().hasName("SSL *")
and func_1(vs_273)
and vs_273.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
