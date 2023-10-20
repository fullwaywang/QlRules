/**
 * @name openssl-8011cd56e39a433b1837465259a9bd24a38727fb-ssl3_send_client_key_exchange
 * @id cpp/openssl/8011cd56e39a433b1837465259a9bd24a38727fb/ssl3-send-client-key-exchange
 * @description openssl-8011cd56e39a433b1837465259a9bd24a38727fb-ssl3_send_client_key_exchange CVE-2014-3470
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valg_k_2222, Parameter vs_2218) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sess_cert"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_2218
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="10"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_2222
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="224")
}

predicate func_4(Variable vn_2221) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vn_2221
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_6(Parameter vs_2218) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="master_key"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2218)
}

from Function func, Variable vn_2221, Variable valg_k_2222, Parameter vs_2218
where
not func_0(valg_k_2222, vs_2218)
and not func_4(vn_2221)
and vn_2221.getType().hasName("int")
and valg_k_2222.getType().hasName("unsigned long")
and vs_2218.getType().hasName("SSL *")
and func_6(vs_2218)
and vn_2221.getParentScope+() = func
and valg_k_2222.getParentScope+() = func
and vs_2218.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
