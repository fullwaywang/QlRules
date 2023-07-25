/**
 * @name openssl-34628967f1e65dc8f34e000f0f5518e21afbfc7b-tls1_change_cipher_state
 * @id cpp/openssl/34628967f1e65dc8f34e000f0f5518e21afbfc7b/tls1-change-cipher-state
 * @description openssl-34628967f1e65dc8f34e000f0f5518e21afbfc7b-tls1_change_cipher_state CVE-2013-6450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_319, Variable vreuse_dd_341) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreuse_dd_341
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("EVP_CIPHER_CTX_new")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vs_319, Parameter vwhich_319, Variable vmac_ctx_338) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmac_ctx_338
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_MD_CTX_create")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmac_ctx_338
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="write_hash"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmac_ctx_338
		and target_2.getElse() instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vwhich_319
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_6(Parameter vs_319, Variable vreuse_dd_341) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="enc_write_ctx"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_6.getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreuse_dd_341
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_7(Parameter vs_319) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="enc_write_ctx"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_319
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_8(Parameter vs_319, Parameter vwhich_319, Variable vmac_ctx_338) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmac_ctx_338
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssl_replace_hash")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="write_hash"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vwhich_319
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_9(Function func) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("CRYPTO_malloc")
		and target_9.getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getArgument(0).(SizeofTypeOperator).getValue()="168"
		and target_9.getArgument(1) instanceof StringLiteral
		and target_9.getArgument(2) instanceof Literal
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vs_319) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("EVP_CIPHER_CTX_init")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="enc_write_ctx"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319)
}

predicate func_11(Parameter vs_319) {
	exists(AssignAndExpr target_11 |
		target_11.getLValue().(PointerFieldAccess).getTarget().getName()="mac_flags"
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319
		and target_11.getRValue().(ComplementExpr).getValue()="-3")
}

predicate func_12(Parameter vs_319, Variable vdd_330) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getTarget()=vdd_330
		and target_12.getRValue().(PointerFieldAccess).getTarget().getName()="enc_write_ctx"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_319)
}

from Function func, Parameter vs_319, Parameter vwhich_319, Variable vdd_330, Variable vmac_ctx_338, Variable vreuse_dd_341
where
not func_0(vs_319, vreuse_dd_341)
and not func_1(func)
and not func_2(vs_319, vwhich_319, vmac_ctx_338)
and func_6(vs_319, vreuse_dd_341)
and func_7(vs_319)
and func_8(vs_319, vwhich_319, vmac_ctx_338)
and func_9(func)
and func_10(vs_319)
and vs_319.getType().hasName("SSL *")
and func_11(vs_319)
and func_12(vs_319, vdd_330)
and vwhich_319.getType().hasName("int")
and vdd_330.getType().hasName("EVP_CIPHER_CTX *")
and vmac_ctx_338.getType().hasName("EVP_MD_CTX *")
and vreuse_dd_341.getType().hasName("int")
and vs_319.getParentScope+() = func
and vwhich_319.getParentScope+() = func
and vdd_330.getParentScope+() = func
and vmac_ctx_338.getParentScope+() = func
and vreuse_dd_341.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
