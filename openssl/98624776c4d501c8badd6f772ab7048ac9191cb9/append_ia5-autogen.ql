import cpp

predicate func_0(Parameter vemail, Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("CRYPTO_strdup")
		and not target_0.getTarget().hasName("CRYPTO_strndup")
		and target_0.getType().hasName("char *")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(0).(PointerFieldAccess).getType().hasName("unsigned char *")
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail
		and target_0.getArgument(1) instanceof StringLiteral
		and target_0.getArgument(2) instanceof Literal
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Parameter vemail) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("memchr")
		and target_3.getType().hasName("void *")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArgument(0).(PointerFieldAccess).getType().hasName("unsigned char *")
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail
		and target_3.getArgument(1).(Literal).getValue()="0"
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getArgument(2).(PointerFieldAccess).getType().hasName("int")
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail)
}

predicate func_6(Parameter vsk, Variable vemtmp, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NEExpr).getType().hasName("int")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getTarget().hasName("OPENSSL_sk_find")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_sk_type")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(0).(FunctionCall).getType().hasName("OPENSSL_STACK *")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_type")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(1).(FunctionCall).getType().hasName("char *")
		and target_6.getCondition().(NEExpr).getLeftOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp
		and target_6.getCondition().(NEExpr).getRightOperand().(UnaryMinusExpr).getType().hasName("int")
		and target_6.getCondition().(NEExpr).getRightOperand().(UnaryMinusExpr).getValue()="-1"
		and target_6.getCondition().(NEExpr).getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_6.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_8(Parameter vsk, Variable vemtmp, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(NotExpr).getType().hasName("int")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("OPENSSL_sk_push")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_sk_type")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(FunctionCall).getType().hasName("OPENSSL_STACK *")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_type")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getType().hasName("char *")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("X509_email_free")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getType().hasName("stack_st_OPENSSL_STRING *")
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_8.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_10(Parameter vemail) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="data"
		and target_10.getType().hasName("unsigned char *")
		and target_10.getQualifier().(VariableAccess).getTarget()=vemail)
}

predicate func_11(Parameter vemail) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="length"
		and target_11.getType().hasName("int")
		and target_11.getQualifier().(VariableAccess).getTarget()=vemail)
}

predicate func_18(Parameter vsk, Variable vemtmp, Function func) {
	exists(LogicalOrExpr target_18 |
		target_18.getType().hasName("int")
		and target_18.getLeftOperand() instanceof EQExpr
		and target_18.getRightOperand() instanceof NotExpr
		and target_18.getEnclosingFunction() = func
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("X509_email_free")
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_18.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vsk, Parameter vemail, Variable vemtmp
where
func_0(vemail, func)
and not func_3(vemail)
and not func_6(vsk, vemtmp, func)
and not func_8(vsk, vemtmp, func)
and func_10(vemail)
and func_11(vemail)
and func_18(vsk, vemtmp, func)
and vsk.getType().hasName("stack_st_OPENSSL_STRING **")
and vemail.getType().hasName("const ASN1_IA5STRING *")
and vemtmp.getType().hasName("char *")
and vsk.getParentScope+() = func
and vemail.getParentScope+() = func
and vemtmp.getParentScope+() = func
select func, vsk, vemail, vemtmp
