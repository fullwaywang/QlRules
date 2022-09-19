import cpp

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="255"
		and not target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="274"
		and not target_3.getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vpkt, Variable vtmp, Variable vmsglen) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("WPACKET_memcpy")
		and not target_4.getTarget().hasName("WPACKET_allocate_bytes")
		and target_4.getType().hasName("int")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vpkt
		and target_4.getArgument(1).(VariableAccess).getTarget()=vtmp
		and target_4.getArgument(2).(VariableAccess).getTarget()=vmsglen)
}

predicate func_5(Function func) {
	exists(BitwiseOrExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getValue()="786691"
		and target_5.getLeftOperand().(Literal).getValue()="259"
		and target_5.getRightOperand().(BitwiseOrExpr).getType().hasName("int")
		and target_5.getRightOperand().(BitwiseOrExpr).getValue()="786432"
		and target_5.getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getType().hasName("int")
		and target_5.getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getValue()="262144"
		and target_5.getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_5.getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="18"
		and target_5.getRightOperand().(BitwiseOrExpr).getRightOperand() instanceof LShiftExpr
		and target_5.getEnclosingFunction() = func)
}

predicate func_9(Parameter vs, Parameter vpkt, Variable vpkey_ctx, Variable vpms, Variable vpmslen, Variable vmsglen, Variable v__func__) {
	exists(LogicalOrExpr target_9 |
		target_9.getType().hasName("int")
		and target_9.getLeftOperand().(NotExpr).getType().hasName("int")
		and target_9.getLeftOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WPACKET_allocate_bytes")
		and target_9.getLeftOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_9.getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkt
		and target_9.getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsglen
		and target_9.getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("unsigned char **")
		and target_9.getRightOperand().(LEExpr).getType().hasName("int")
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getTarget().hasName("EVP_PKEY_encrypt")
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkey_ctx
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmsglen
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpms
		and target_9.getRightOperand().(LEExpr).getLesserOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpmslen
		and target_9.getRightOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="80"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="6"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="2"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="18"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_12(Variable vpkey_ctx) {
	exists(AssignExpr target_12 |
		target_12.getType().hasName("EVP_PKEY_CTX *")
		and target_12.getLValue().(VariableAccess).getTarget()=vpkey_ctx
		and target_12.getRValue().(Literal).getValue()="0")
}

predicate func_13(Function func) {
	exists(LShiftExpr target_13 |
		target_13.getType().hasName("int")
		and target_13.getValue()="524288"
		and target_13.getLeftOperand().(Literal).getValue()="2"
		and target_13.getRightOperand().(Literal).getValue()="18"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(VariableAccess target_14 |
		target_14.getParent().(AssignExpr).getRValue() instanceof Literal
		and target_14.getEnclosingFunction() = func)
}

predicate func_15() {
	exists(VariableDeclarationEntry target_15 |
		target_15.getType().hasName("unsigned char[255]"))
}

predicate func_16(Variable vmsglen, Function func) {
	exists(AssignExpr target_16 |
		target_16.getType().hasName("size_t")
		and target_16.getLValue().(VariableAccess).getTarget()=vmsglen
		and target_16.getRValue() instanceof Literal
		and target_16.getEnclosingFunction() = func)
}

from Function func, Parameter vs, Parameter vpkt, Variable vtmp, Variable vpkey_ctx, Variable vpms, Variable vpmslen, Variable vmsglen, Variable v__func__
where
func_2(func)
and func_3(func)
and func_4(vpkt, vtmp, vmsglen)
and func_5(func)
and not func_9(vs, vpkt, vpkey_ctx, vpms, vpmslen, vmsglen, v__func__)
and not func_12(vpkey_ctx)
and func_13(func)
and func_14(func)
and func_15()
and func_16(vmsglen, func)
and vs.getType().hasName("SSL *")
and vpkt.getType().hasName("WPACKET *")
and vpkey_ctx.getType().hasName("EVP_PKEY_CTX *")
and vpms.getType().hasName("unsigned char *")
and vpmslen.getType().hasName("size_t")
and vmsglen.getType().hasName("size_t")
and v__func__.getType().hasName("const char[25]")
and vs.getParentScope+() = func
and vpkt.getParentScope+() = func
and vtmp.getParentScope+() = func
and vpkey_ctx.getParentScope+() = func
and vpms.getParentScope+() = func
and vpmslen.getParentScope+() = func
and vmsglen.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, vs, vpkt, vtmp, vpkey_ctx, vpms, vpmslen, vmsglen, v__func__
