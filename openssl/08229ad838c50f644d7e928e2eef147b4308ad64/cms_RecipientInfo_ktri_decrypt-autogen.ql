/**
 * @name openssl-08229ad838c50f644d7e928e2eef147b4308ad64-cms_RecipientInfo_ktri_decrypt
 * @id cpp/openssl/08229ad838c50f644d7e928e2eef147b4308ad64/cms-RecipientInfo-ktri-decrypt
 * @description openssl-08229ad838c50f644d7e928e2eef147b4308ad64-cms_RecipientInfo_ktri_decrypt CVE-2019-1547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(5)=target_0)
}

predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const EVP_CIPHER *")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="havenocert"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="debug"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable veklen_364, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_364
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veklen_364
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="46"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="140"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="104"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_8))
}

predicate func_9(Variable vktri_361, Variable vek_363, Variable veklen_364) {
	exists(RelationalOperation target_9 |
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pctx"
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361
		and target_9.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek_363
		and target_9.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen_364
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361
		and target_9.getGreaterOperand().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="46"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="140"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="104"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_10(Parameter vcms_358) {
	exists(ValueFieldAccess target_10 |
		target_10.getTarget().getName()="envelopedData"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcms_358)
}

predicate func_11(Variable vktri_361, Variable vek_363, Variable veklen_364) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(VariableAccess).getTarget()=veklen_364
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pctx"
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek_363
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_11.getParent().(FunctionCall).getParent().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri_361)
}

predicate func_12(Parameter vcms_358, Variable vec_366) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getTarget()=vec_366
		and target_12.getRValue().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcms_358)
}

from Function func, Parameter vcms_358, Variable vktri_361, Variable vek_363, Variable veklen_364, Variable vec_366
where
not func_0(func)
and not func_7(func)
and not func_8(veklen_364, func)
and func_9(vktri_361, vek_363, veklen_364)
and vcms_358.getType().hasName("CMS_ContentInfo *")
and func_10(vcms_358)
and vktri_361.getType().hasName("CMS_KeyTransRecipientInfo *")
and vek_363.getType().hasName("unsigned char *")
and veklen_364.getType().hasName("size_t")
and func_11(vktri_361, vek_363, veklen_364)
and vec_366.getType().hasName("CMS_EncryptedContentInfo *")
and func_12(vcms_358, vec_366)
and vcms_358.getParentScope+() = func
and vktri_361.getParentScope+() = func
and vek_363.getParentScope+() = func
and veklen_364.getParentScope+() = func
and vec_366.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
