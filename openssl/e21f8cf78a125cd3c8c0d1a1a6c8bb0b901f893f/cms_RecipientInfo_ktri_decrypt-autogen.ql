/**
 * @name openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-cms_RecipientInfo_ktri_decrypt
 * @id cpp/openssl/e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f/cms-RecipientInfo-ktri-decrypt
 * @description openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-crypto/cms/cms_env.c-cms_RecipientInfo_ktri_decrypt CVE-2019-1563
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcms_417, BlockStmt target_5, ValueFieldAccess target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="havenocert"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcms_417
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="debug"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcms_417
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const EVP_CIPHER *")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(RelationalOperation target_4, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const EVP_CIPHER *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable veklen_423, AddressOfExpr target_7, ExprStmt target_8, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_423
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_423
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_3)
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Variable vktri_420, Variable vek_422, Variable veklen_423, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pctx"
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_420
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek_422
		and target_4.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen_423
		and target_4.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_4.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_420
		and target_4.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_4.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_420
		and target_4.getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_6(Parameter vcms_417, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="envelopedData"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcms_417
}

predicate func_7(Variable veklen_423, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=veklen_423
}

predicate func_8(Variable veklen_423, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="keylen"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=veklen_423
}

from Function func, Parameter vcms_417, Variable vktri_420, Variable vek_422, Variable veklen_423, RelationalOperation target_4, BlockStmt target_5, ValueFieldAccess target_6, AddressOfExpr target_7, ExprStmt target_8
where
not func_0(vcms_417, target_5, target_6)
and not func_1(target_4, func)
and not func_2(target_4, func)
and not func_3(veklen_423, target_7, target_8, func)
and func_4(vktri_420, vek_422, veklen_423, target_5, target_4)
and func_5(target_5)
and func_6(vcms_417, target_6)
and func_7(veklen_423, target_7)
and func_8(veklen_423, target_8)
and vcms_417.getType().hasName("CMS_ContentInfo *")
and vktri_420.getType().hasName("CMS_KeyTransRecipientInfo *")
and vek_422.getType().hasName("unsigned char *")
and veklen_423.getType().hasName("size_t")
and vcms_417.getParentScope+() = func
and vktri_420.getParentScope+() = func
and vek_422.getParentScope+() = func
and veklen_423.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
