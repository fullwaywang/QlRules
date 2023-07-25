/**
 * @name openssl-1392c238657e-ssl3_send_client_key_exchange
 * @id cpp/openssl/1392c238657e/ssl3-send-client-key-exchange
 * @description openssl-1392c238657e-ssl/s3_clnt.c-ssl3_send_client_key_exchange CVE-2015-3196
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_2019, ExprStmt target_3, EqualityOperation target_4) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="session"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_2019
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_2019, VariableAccess target_1) {
		target_1.getTarget()=vs_2019
}

predicate func_2(Parameter vs_2019, EqualityOperation target_4, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ctx"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_2019
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_3(Parameter vs_2019, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="psk_client_callback"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2019
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vs_2019
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2019
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(SubExpr).getValue()="129"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(5).(SizeofExprOperator).getValue()="516"
}

predicate func_4(Parameter vs_2019, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2019
		and target_4.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vs_2019, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3, EqualityOperation target_4
where
not func_0(vs_2019, target_3, target_4)
and func_1(vs_2019, target_1)
and func_2(vs_2019, target_4, target_2)
and func_3(vs_2019, target_3)
and func_4(vs_2019, target_4)
and vs_2019.getType().hasName("SSL *")
and vs_2019.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
