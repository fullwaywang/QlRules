/**
 * @name openssl-d81a1600588b726c2bdccda7efad3cc7a87d6245-get_client_master_key
 * @id cpp/openssl/d81a1600588b726c2bdccda7efad3cc7a87d6245/get-client-master-key
 * @description openssl-d81a1600588b726c2bdccda7efad3cc7a87d6245-get_client_master_key CVE-2015-3197
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_373, Variable vcp_379) {
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
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_1(Parameter vs_373, Variable vcp_379) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vcp_379
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_2(Parameter vs_373) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ssl2_return_error")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_373
		and target_2.getArgument(1).(Literal).getValue()="0")
}

predicate func_3(Variable vp_378, Variable vcp_379) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vcp_379
		and target_3.getRValue().(FunctionCall).getTarget().hasName("ssl2_get_cipher_by_char")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_378)
}

from Function func, Parameter vs_373, Variable vp_378, Variable vcp_379
where
not func_0(vs_373, vcp_379)
and func_1(vs_373, vcp_379)
and vs_373.getType().hasName("SSL *")
and func_2(vs_373)
and vcp_379.getType().hasName("const SSL_CIPHER *")
and func_3(vp_378, vcp_379)
and vs_373.getParentScope+() = func
and vp_378.getParentScope+() = func
and vcp_379.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
