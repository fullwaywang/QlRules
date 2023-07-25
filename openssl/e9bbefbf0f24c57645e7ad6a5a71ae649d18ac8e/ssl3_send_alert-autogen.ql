/**
 * @name openssl-e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e-ssl3_send_alert
 * @id cpp/openssl/e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e/ssl3-send-alert
 * @description openssl-e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e-ssl/s3_pkt.c-ssl3_send_alert CVE-2019-1559
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1713, LogicalAndExpr target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof EqualityOperation
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1713, LogicalAndExpr target_4, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_1.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="12293"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vlevel_1713, Parameter vs_1713, ExprStmt target_6, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vlevel_1713
		and target_2.getAnOperand().(Literal).getValue()="2"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_3(Parameter vlevel_1713, Parameter vs_1713, ExprStmt target_6, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="session"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlevel_1713
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_4(ExprStmt target_6, Function func, LogicalAndExpr target_4) {
		target_4.getAnOperand() instanceof EqualityOperation
		and target_4.getAnOperand() instanceof EqualityOperation
		and target_4.getParent().(IfStmt).getThen()=target_6
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vs_1713, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alert_dispatch"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_6(Parameter vs_1713, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1713
}

from Function func, Parameter vlevel_1713, Parameter vs_1713, LogicalAndExpr target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vs_1713, target_4, target_5)
and not func_1(vs_1713, target_4, target_6)
and func_4(target_6, func, target_4)
and func_5(vs_1713, target_5)
and func_6(vs_1713, target_6)
and vlevel_1713.getType().hasName("int")
and vs_1713.getType().hasName("SSL *")
and vlevel_1713.getParentScope+() = func
and vs_1713.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
