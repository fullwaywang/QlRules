import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="211"
		and not target_0.getValue()="212"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="219"
		and not target_1.getValue()="220"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="222"
		and not target_2.getValue()="223"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="229"
		and not target_3.getValue()="232"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vri, Variable vpctx, Variable vek, Variable veklen, Variable vret) {
	exists(LogicalOrExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpctx
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri
		and target_4.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=veklen
		and target_4.getLeftOperand().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_4.getRightOperand().(LogicalAndExpr).getType().hasName("int")
		and target_4.getRightOperand().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_4.getRightOperand().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_4.getRightOperand().(LogicalAndExpr).getRightOperand().(NEExpr).getType().hasName("int")
		and target_4.getRightOperand().(LogicalAndExpr).getRightOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=veklen
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="33"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="pk7_doit.c"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="232")
}

predicate func_5(Parameter vri, Variable vpctx, Variable vek, Variable veklen, Variable vret) {
	exists(LEExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_decrypt")
		and target_5.getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_5.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpctx
		and target_5.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vek
		and target_5.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_5.getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veklen
		and target_5.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getType().hasName("unsigned char *")
		and target_5.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_5.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_5.getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri
		and target_5.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getType().hasName("int")
		and target_5.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="enc_key"
		and target_5.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ASN1_OCTET_STRING *")
		and target_5.getLesserOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vri
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="33"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="133"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="pk7_doit.c"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Parameter vri, Variable vpctx, Variable vek, Variable veklen, Variable vret
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_4(vri, vpctx, vek, veklen, vret)
and func_5(vri, vpctx, vek, veklen, vret)
and vri.getType().hasName("PKCS7_RECIP_INFO *")
and vpctx.getType().hasName("EVP_PKEY_CTX *")
and vek.getType().hasName("unsigned char *")
and veklen.getType().hasName("size_t")
and vret.getType().hasName("int")
and vri.getParentScope+() = func
and vpctx.getParentScope+() = func
and vek.getParentScope+() = func
and veklen.getParentScope+() = func
and vret.getParentScope+() = func
select func, vri, vpctx, vek, veklen, vret
