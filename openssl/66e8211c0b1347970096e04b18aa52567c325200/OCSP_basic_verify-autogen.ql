import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="98"
		and not target_0.getValue()="101"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="112"
		and not target_1.getValue()="115"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="123"
		and not target_2.getValue()="126"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="149"
		and not target_3.getValue()="152"
		and target_3.getEnclosingFunction() = func)
}

predicate func_6(Variable vret, Variable vskey, Parameter vflags) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalOrExpr).getLeftOperand().(NotExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vskey
		and target_6.getCondition().(LogicalOrExpr).getRightOperand().(LEExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalOrExpr).getRightOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_6.getCondition().(LogicalOrExpr).getRightOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="39"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="105"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="117"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ocsp_vfy.c"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="101"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_7(Variable vret, Variable vskey, Variable vOCSP_RESPDATA_it, Parameter vflags, Parameter vbs) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_verify")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("const ASN1_ITEM *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vOCSP_RESPDATA_it
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="signatureAlgorithm"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("X509_ALGOR *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="signature"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getType().hasName("ASN1_BIT_STRING *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tbsResponseData"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("OCSP_RESPDATA *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vskey
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_8(Variable vskey, Parameter vflags) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("EVP_PKEY_free")
		and target_8.getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskey
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_9(Variable vret) {
	exists(LEExpr target_9 |
		target_9.getType().hasName("int")
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vret
		and target_9.getGreaterOperand().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="39"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="105"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="117"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ocsp_vfy.c"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Variable vret, Variable vskey, Variable vOCSP_RESPDATA_it, Parameter vflags, Parameter vbs
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_6(vret, vskey, vflags)
and func_7(vret, vskey, vOCSP_RESPDATA_it, vflags, vbs)
and func_8(vskey, vflags)
and func_9(vret)
and vret.getType().hasName("int")
and vskey.getType().hasName("EVP_PKEY *")
and vOCSP_RESPDATA_it.getType().hasName("const ASN1_ITEM")
and vflags.getType().hasName("unsigned long")
and vbs.getType().hasName("OCSP_BASICRESP *")
and vret.getParentScope+() = func
and vskey.getParentScope+() = func
and not vOCSP_RESPDATA_it.getParentScope+() = func
and vflags.getParentScope+() = func
and vbs.getParentScope+() = func
select func, vret, vskey, vOCSP_RESPDATA_it, vflags, vbs
