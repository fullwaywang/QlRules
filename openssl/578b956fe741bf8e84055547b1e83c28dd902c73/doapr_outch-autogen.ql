import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="713"
		and not target_0.getValue()="755"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="724"
		and not target_1.getValue()="765"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vmaxlen) {
	exists(GTExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getGreaterOperand().(PointerDereferenceExpr).getType().hasName("size_t")
		and target_2.getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmaxlen
		and target_2.getLesserOperand().(SubExpr).getType().hasName("int")
		and target_2.getLesserOperand().(SubExpr).getValue()="2147482623"
		and target_2.getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1024")
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("char *")
		and target_6.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EQExpr).getType().hasName("int")
		and target_9.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_9.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_9.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vbuffer) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getType().hasName("char *")
		and target_10.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getType().hasName("char *")
		and target_10.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuffer
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *"))
}

predicate func_12(Parameter vbuffer) {
	exists(EQExpr target_12 |
		target_12.getType().hasName("int")
		and target_12.getLeftOperand().(PointerDereferenceExpr).getType().hasName("char *")
		and target_12.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuffer
		and target_12.getRightOperand().(Literal).getValue()="0")
}

predicate func_13(Parameter vmaxlen) {
	exists(PointerDereferenceExpr target_13 |
		target_13.getType().hasName("size_t")
		and target_13.getOperand().(VariableAccess).getTarget()=vmaxlen)
}

predicate func_14(Parameter vbuffer) {
	exists(PointerDereferenceExpr target_14 |
		target_14.getType().hasName("char *")
		and target_14.getOperand().(VariableAccess).getTarget()=vbuffer)
}

predicate func_15(Parameter vbuffer) {
	exists(PointerDereferenceExpr target_15 |
		target_15.getType().hasName("char *")
		and target_15.getOperand().(VariableAccess).getTarget()=vbuffer)
}

predicate func_19(Function func) {
	exists(NotExpr target_19 |
		target_19.getType().hasName("int")
		and target_19.getOperand() instanceof PointerDereferenceExpr
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Parameter vbuffer, Parameter vmaxlen, Function func) {
	exists(BlockStmt target_20 |
		target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("char *")
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_realloc")
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("void *")
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuffer
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmaxlen
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="b_print.c"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3) instanceof Literal
		and target_20.getStmt(1).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_20.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand() instanceof PointerDereferenceExpr
		and target_20.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_20.getEnclosingFunction() = func)
}

from Function func, Parameter vbuffer, Parameter vmaxlen
where
func_0(func)
and func_1(func)
and not func_2(vmaxlen)
and not func_6(func)
and not func_9(func)
and not func_10(vbuffer)
and func_12(vbuffer)
and func_13(vmaxlen)
and func_14(vbuffer)
and func_15(vbuffer)
and func_19(func)
and func_20(vbuffer, vmaxlen, func)
and vbuffer.getType().hasName("char **")
and vmaxlen.getType().hasName("size_t *")
and vbuffer.getParentScope+() = func
and vmaxlen.getParentScope+() = func
select func, vbuffer, vmaxlen
