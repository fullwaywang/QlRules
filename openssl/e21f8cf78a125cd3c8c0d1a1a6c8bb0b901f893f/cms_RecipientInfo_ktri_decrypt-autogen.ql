import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="429"
		and not target_0.getValue()="430"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="445"
		and not target_1.getValue()="459"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="454"
		and not target_2.getValue()="468"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="457"
		and not target_3.getValue()="471"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="464"
		and not target_4.getValue()="480"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("size_t")
		and target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_8(Variable vktri, Variable vek, Variable veklen, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pctx"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=veklen
		and target_8.getCondition().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getRightOperand().(LogicalAndExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getRightOperand().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getRightOperand().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getRightOperand().(LogicalAndExpr).getRightOperand().(NEExpr).getType().hasName("int")
		and target_8.getCondition().(LogicalOrExpr).getRightOperand().(LogicalAndExpr).getRightOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=veklen
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="46"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="140"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="104"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cms_env.c"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="480"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable vktri, Variable vek, Variable veklen) {
	exists(LEExpr target_9 |
		target_9.getType().hasName("int")
		and target_9.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_9.getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pctx"
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("EVP_PKEY_CTX *")
		and target_9.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_9.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek
		and target_9.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_9.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("unsigned char *")
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_9.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getType().hasName("int")
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedKey"
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_9.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vktri
		and target_9.getGreaterOperand().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="46"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="140"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="104"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cms_env.c"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Parameter vcms, Variable vktri, Variable vek, Variable veklen, Variable vec
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and not func_5(func)
and not func_8(vktri, vek, veklen, func)
and func_9(vktri, vek, veklen)
and vcms.getType().hasName("CMS_ContentInfo *")
and vktri.getType().hasName("CMS_KeyTransRecipientInfo *")
and vek.getType().hasName("unsigned char *")
and veklen.getType().hasName("size_t")
and vec.getType().hasName("CMS_EncryptedContentInfo *")
and vcms.getParentScope+() = func
and vktri.getParentScope+() = func
and vek.getParentScope+() = func
and veklen.getParentScope+() = func
and vec.getParentScope+() = func
select func, vcms, vktri, vek, veklen, vec
