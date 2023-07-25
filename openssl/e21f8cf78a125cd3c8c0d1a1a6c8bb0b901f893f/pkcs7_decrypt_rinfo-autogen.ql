/**
 * @name openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-pkcs7_decrypt_rinfo
 * @id cpp/openssl/e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f/pkcs7-decrypt-rinfo
 * @description openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-crypto/pkcs7/pk7_doit.c-pkcs7_decrypt_rinfo CVE-2019-1563
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable veklen_198, BlockStmt target_2, ExprStmt target_3, AddressOfExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_198
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_198
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vri_194, Variable vpctx_196, Variable vek_197, Variable veklen_198, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_1.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpctx_196
		and target_1.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek_197
		and target_1.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen_198
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri_194
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri_194
		and target_1.getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_3(Variable vek_197, Variable veklen_198, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vek_197
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veklen_198
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_4(Variable veklen_198, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=veklen_198
}

from Function func, Parameter vri_194, Variable vpctx_196, Variable vek_197, Variable veklen_198, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(veklen_198, target_2, target_3, target_4)
and func_1(vri_194, vpctx_196, vek_197, veklen_198, target_2, target_1)
and func_2(target_2)
and func_3(vek_197, veklen_198, target_3)
and func_4(veklen_198, target_4)
and vri_194.getType().hasName("PKCS7_RECIP_INFO *")
and vpctx_196.getType().hasName("EVP_PKEY_CTX *")
and vek_197.getType().hasName("unsigned char *")
and veklen_198.getType().hasName("size_t")
and vri_194.getParentScope+() = func
and vpctx_196.getParentScope+() = func
and vek_197.getParentScope+() = func
and veklen_198.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
