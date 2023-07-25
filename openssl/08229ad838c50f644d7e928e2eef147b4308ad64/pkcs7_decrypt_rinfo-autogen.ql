/**
 * @name openssl-08229ad838c50f644d7e928e2eef147b4308ad64-pkcs7_decrypt_rinfo
 * @id cpp/openssl/08229ad838c50f644d7e928e2eef147b4308ad64/pkcs7-decrypt-rinfo
 * @description openssl-08229ad838c50f644d7e928e2eef147b4308ad64-pkcs7_decrypt_rinfo CVE-2019-1547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable veklen_144, Variable vret_146) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_144
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_144
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_146
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="33"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_1(Parameter vri_140, Variable vpctx_142, Variable vek_143, Variable veklen_144, Variable vret_146) {
	exists(RelationalOperation target_1 |
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
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_146
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="33"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_2(Variable vek_143, Variable veklen_144) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vek_143
		and target_2.getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veklen_144
		and target_2.getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

from Function func, Parameter vri_140, Variable vpctx_142, Variable vek_143, Variable veklen_144, Variable vret_146
where
not func_0(veklen_144, vret_146)
and func_1(vri_140, vpctx_142, vek_143, veklen_144, vret_146)
and vri_140.getType().hasName("PKCS7_RECIP_INFO *")
and vpctx_142.getType().hasName("EVP_PKEY_CTX *")
and vek_143.getType().hasName("unsigned char *")
and veklen_144.getType().hasName("size_t")
and func_2(vek_143, veklen_144)
and vret_146.getType().hasName("int")
and vri_140.getParentScope+() = func
and vpctx_142.getParentScope+() = func
and vek_143.getParentScope+() = func
and veklen_144.getParentScope+() = func
and vret_146.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
