/**
 * @name openssl-631f94db0065c78181ca9ba5546ebc8bb3884b97-pkcs7_decrypt_rinfo
 * @id cpp/openssl/631f94db0065c78181ca9ba5546ebc8bb3884b97/pkcs7-decrypt-rinfo
 * @description openssl-631f94db0065c78181ca9ba5546ebc8bb3884b97-crypto/pkcs7/pk7_doit.c-pkcs7_decrypt_rinfo CVE-2019-1563
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable veklen_144, BlockStmt target_2, ExprStmt target_3, AddressOfExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_144
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_144
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vri_140, Variable vpctx_142, Variable vek_143, Variable veklen_144, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_1.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpctx_142
		and target_1.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek_143
		and target_1.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen_144
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_1.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri_140
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_1.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri_140
		and target_1.getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="33"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_3(Variable vek_143, Variable veklen_144, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vek_143
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veklen_144
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_4(Variable veklen_144, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=veklen_144
}

from Function func, Parameter vri_140, Variable vpctx_142, Variable vek_143, Variable veklen_144, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(veklen_144, target_2, target_3, target_4)
and func_1(vri_140, vpctx_142, vek_143, veklen_144, target_2, target_1)
and func_2(target_2)
and func_3(vek_143, veklen_144, target_3)
and func_4(veklen_144, target_4)
and vri_140.getType().hasName("PKCS7_RECIP_INFO *")
and vpctx_142.getType().hasName("EVP_PKEY_CTX *")
and vek_143.getType().hasName("unsigned char *")
and veklen_144.getType().hasName("size_t")
and vri_140.getParentScope+() = func
and vpctx_142.getParentScope+() = func
and vek_143.getParentScope+() = func
and veklen_144.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
