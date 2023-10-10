/**
 * @name openssl-4040a7fd104b412bd446338c6c28a62eb7d8e852-get_client_master_key
 * @id cpp/openssl/4040a7fd104b412bd446338c6c28a62eb7d8e852/get-client-master-key
 * @description openssl-4040a7fd104b412bd446338c6c28a62eb7d8e852-ssl/s2_srvr.c-get_client_master_key CVE-2015-3197
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_373, Variable vcp_379, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_373
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vcp_379
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcp_379, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vcp_379
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vs_373, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_3(Parameter vs_373, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_4(Parameter vs_373, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_5(Variable vcp_379, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcp_379
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssl2_get_cipher_by_char")
}

from Function func, Parameter vs_373, Variable vcp_379, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vs_373, vcp_379, target_2, target_3, target_4, target_5, target_1)
and func_1(vcp_379, target_2, target_1)
and func_2(vs_373, target_2)
and func_3(vs_373, target_3)
and func_4(vs_373, target_4)
and func_5(vcp_379, target_5)
and vs_373.getType().hasName("SSL *")
and vcp_379.getType().hasName("const SSL_CIPHER *")
and vs_373.getParentScope+() = func
and vcp_379.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
