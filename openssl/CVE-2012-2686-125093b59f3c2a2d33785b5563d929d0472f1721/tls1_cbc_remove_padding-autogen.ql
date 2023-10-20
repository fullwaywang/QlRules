/**
 * @name openssl-125093b59f3c2a2d33785b5563d929d0472f1721-tls1_cbc_remove_padding
 * @id cpp/openssl/125093b59f3c2a2d33785b5563d929d0472f1721/tls1-cbc-remove-padding
 * @description openssl-125093b59f3c2a2d33785b5563d929d0472f1721-tls1_cbc_remove_padding CVE-2012-2686
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_136, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_flags")
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_read_ctx"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_136
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2097152"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_2(Parameter vrec_137, Variable vpadding_length_141, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrec_137
		and target_2.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vpadding_length_141
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_2))
}

predicate func_4(Parameter vrec_137, Variable vpadding_length_141) {
	exists(AssignSubExpr target_4 |
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrec_137
		and target_4.getRValue().(VariableAccess).getTarget()=vpadding_length_141)
}

predicate func_5(Parameter vs_136, Variable vpadding_length_141) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_5.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_136
		and target_5.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpadding_length_141
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpadding_length_141)
}

from Function func, Parameter vrec_137, Parameter vs_136, Variable vpadding_length_141
where
not func_0(vs_136, func)
and not func_2(vrec_137, vpadding_length_141, func)
and vrec_137.getType().hasName("SSL3_RECORD *")
and func_4(vrec_137, vpadding_length_141)
and vs_136.getType().hasName("const SSL *")
and func_5(vs_136, vpadding_length_141)
and vpadding_length_141.getType().hasName("unsigned int")
and vrec_137.getParentScope+() = func
and vs_136.getParentScope+() = func
and vpadding_length_141.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
