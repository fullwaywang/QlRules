import cpp

predicate func_0(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="32"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vprefix) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerDereferenceExpr).getType().hasName("char")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vprefix
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getType().hasName("int")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="48"
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vconvert, Variable vplace) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getType().hasName("char")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vconvert
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vplace
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vspadlen) {
	exists(BlockStmt target_5 |
		target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_5.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="32"
		and target_5.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_5.getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getType().hasName("int")
		and target_5.getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vspadlen)
}

predicate func_7(Variable vprefix) {
	exists(PointerDereferenceExpr target_7 |
		target_7.getType().hasName("char")
		and target_7.getOperand().(VariableAccess).getTarget()=vprefix)
}

predicate func_8(Variable vconvert, Variable vplace) {
	exists(ArrayExpr target_8 |
		target_8.getType().hasName("char")
		and target_8.getArrayBase().(VariableAccess).getTarget()=vconvert
		and target_8.getArrayOffset().(PrefixDecrExpr).getType().hasName("int")
		and target_8.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vplace)
}

predicate func_9(Variable vspadlen) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(PrefixIncrExpr).getType().hasName("int")
		and target_9.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vspadlen)
}

predicate func_14(Function func) {
	exists(CharLiteral target_14 |
		target_14.getValue()="32"
		and target_14.getEnclosingFunction() = func)
}

predicate func_28(Function func) {
	exists(CharLiteral target_28 |
		target_28.getValue()="48"
		and target_28.getEnclosingFunction() = func)
}

predicate func_38(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_38 |
		target_38.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_38.getExpr().(FunctionCall).getType().hasName("void")
		and target_38.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_38.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_38.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_38.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_38.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_38.getEnclosingFunction() = func)
}

predicate func_39(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue) {
	exists(ExprStmt target_39 |
		target_39.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_39.getExpr().(FunctionCall).getType().hasName("void")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_39.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_39.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_39.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_39.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue)
}

predicate func_40(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_40 |
		target_40.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_40.getExpr().(FunctionCall).getType().hasName("void")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_40.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_40.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_40.getExpr().(FunctionCall).getArgument(4) instanceof PointerDereferenceExpr
		and target_40.getEnclosingFunction() = func)
}

predicate func_41(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_41 |
		target_41.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_41.getExpr().(FunctionCall).getType().hasName("void")
		and target_41.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_41.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_41.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_41.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_41.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_41.getEnclosingFunction() = func)
}

predicate func_42(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_42 |
		target_42.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_42.getExpr().(FunctionCall).getType().hasName("void")
		and target_42.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_42.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_42.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_42.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_42.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_42.getEnclosingFunction() = func)
}

from Function func, Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue, Variable vprefix, Variable vconvert, Variable vplace, Variable vspadlen
where
not func_0(vsbuffer, vbuffer, vcurrlen, vmaxlen)
and not func_1(vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue)
and not func_2(vsbuffer, vbuffer, vcurrlen, vmaxlen, vprefix)
and not func_3(vsbuffer, vbuffer, vcurrlen, vmaxlen)
and not func_4(vsbuffer, vbuffer, vcurrlen, vmaxlen, vconvert, vplace)
and not func_5(vsbuffer, vbuffer, vcurrlen, vmaxlen, vspadlen)
and func_7(vprefix)
and func_8(vconvert, vplace)
and func_9(vspadlen)
and func_14(func)
and func_28(func)
and func_38(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_39(vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue)
and func_40(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_41(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_42(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and vsbuffer.getType().hasName("char **")
and vbuffer.getType().hasName("char **")
and vcurrlen.getType().hasName("size_t *")
and vmaxlen.getType().hasName("size_t *")
and vsignvalue.getType().hasName("int")
and vprefix.getType().hasName("const char *")
and vconvert.getType().hasName("char[26]")
and vplace.getType().hasName("int")
and vspadlen.getType().hasName("int")
and vsbuffer.getParentScope+() = func
and vbuffer.getParentScope+() = func
and vcurrlen.getParentScope+() = func
and vmaxlen.getParentScope+() = func
and vsignvalue.getParentScope+() = func
and vprefix.getParentScope+() = func
and vconvert.getParentScope+() = func
and vplace.getParentScope+() = func
and vspadlen.getParentScope+() = func
select func, vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue, vprefix, vconvert, vplace, vspadlen
