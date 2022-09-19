import cpp

predicate func_0(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="48"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="32"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue) {
	exists(LogicalAndExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(VariableAccess).getTarget()=vsignvalue
		and target_3.getRightOperand().(NotExpr).getType().hasName("int")
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_3.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue)
}

predicate func_4(Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable viconvert, Variable viplace) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getType().hasName("int")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getType().hasName("char")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=viconvert
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=viplace
		and target_5.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_6(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getType().hasName("int")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="46"
		and target_6.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_7(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vfconvert, Variable vfplace) {
	exists(IfStmt target_7 |
		target_7.getCondition().(NotExpr).getType().hasName("int")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getType().hasName("char")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfconvert
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vfplace
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_8(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vzpadlen) {
	exists(BlockStmt target_8 |
		target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_8.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="48"
		and target_8.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getStmt(1).(ExprStmt).getExpr().(PrefixDecrExpr).getType().hasName("int")
		and target_8.getStmt(1).(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vzpadlen)
}

predicate func_9(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vpadlen) {
	exists(BlockStmt target_9 |
		target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_9.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="32"
		and target_9.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_9.getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getType().hasName("int")
		and target_9.getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vpadlen)
}

predicate func_11(Variable viconvert, Variable viplace) {
	exists(ArrayExpr target_11 |
		target_11.getType().hasName("char")
		and target_11.getArrayBase().(VariableAccess).getTarget()=viconvert
		and target_11.getArrayOffset().(PrefixDecrExpr).getType().hasName("int")
		and target_11.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=viplace)
}

predicate func_12(Variable vfconvert, Variable vfplace) {
	exists(ArrayExpr target_12 |
		target_12.getType().hasName("char")
		and target_12.getArrayBase().(VariableAccess).getTarget()=vfconvert
		and target_12.getArrayOffset().(PrefixDecrExpr).getType().hasName("int")
		and target_12.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vfplace)
}

predicate func_13(Variable vzpadlen) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(PrefixDecrExpr).getType().hasName("int")
		and target_13.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vzpadlen)
}

predicate func_14(Variable vpadlen) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(PrefixIncrExpr).getType().hasName("int")
		and target_14.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vpadlen)
}

predicate func_24(Function func) {
	exists(CharLiteral target_24 |
		target_24.getValue()="48"
		and target_24.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(CharLiteral target_29 |
		target_29.getValue()="32"
		and target_29.getEnclosingFunction() = func)
}

predicate func_43(Function func) {
	exists(CharLiteral target_43 |
		target_43.getValue()="46"
		and target_43.getEnclosingFunction() = func)
}

predicate func_59(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue) {
	exists(ExprStmt target_59 |
		target_59.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_59.getExpr().(FunctionCall).getType().hasName("void")
		and target_59.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_59.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_59.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_59.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_59.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue)
}

predicate func_60(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_60 |
		target_60.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_60.getExpr().(FunctionCall).getType().hasName("void")
		and target_60.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_60.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_60.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_60.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_60.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_60.getEnclosingFunction() = func)
}

predicate func_61(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_61 |
		target_61.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_61.getExpr().(FunctionCall).getType().hasName("void")
		and target_61.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_61.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_61.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_61.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_61.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_61.getEnclosingFunction() = func)
}

predicate func_63(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_63 |
		target_63.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_63.getExpr().(FunctionCall).getType().hasName("void")
		and target_63.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_63.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_63.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_63.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_63.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_63.getEnclosingFunction() = func)
}

predicate func_64(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_64 |
		target_64.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_64.getExpr().(FunctionCall).getType().hasName("void")
		and target_64.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_64.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_64.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_64.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_64.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_64.getEnclosingFunction() = func)
}

predicate func_65(Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_65 |
		target_65.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_65.getExpr().(FunctionCall).getType().hasName("void")
		and target_65.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_65.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_65.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen
		and target_65.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_65.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_65.getEnclosingFunction() = func)
}

from Function func, Parameter vsbuffer, Parameter vbuffer, Parameter vcurrlen, Parameter vmaxlen, Variable vsignvalue, Variable viconvert, Variable vfconvert, Variable viplace, Variable vfplace, Variable vpadlen, Variable vzpadlen
where
not func_0(vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue)
and not func_1(vsbuffer, vbuffer, vcurrlen, vmaxlen)
and not func_2(vsbuffer, vbuffer, vcurrlen, vmaxlen)
and not func_3(vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue)
and not func_4(func)
and not func_5(vsbuffer, vbuffer, vcurrlen, vmaxlen, viconvert, viplace)
and not func_6(vsbuffer, vbuffer, vcurrlen, vmaxlen)
and not func_7(vsbuffer, vbuffer, vcurrlen, vmaxlen, vfconvert, vfplace)
and not func_8(vsbuffer, vbuffer, vcurrlen, vmaxlen, vzpadlen)
and not func_9(vsbuffer, vbuffer, vcurrlen, vmaxlen, vpadlen)
and func_11(viconvert, viplace)
and func_12(vfconvert, vfplace)
and func_13(vzpadlen)
and func_14(vpadlen)
and func_24(func)
and func_29(func)
and func_43(func)
and func_59(vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue)
and func_60(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_61(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_63(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_64(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and func_65(vsbuffer, vbuffer, vcurrlen, vmaxlen, func)
and vsbuffer.getType().hasName("char **")
and vbuffer.getType().hasName("char **")
and vcurrlen.getType().hasName("size_t *")
and vmaxlen.getType().hasName("size_t *")
and vsignvalue.getType().hasName("int")
and viconvert.getType().hasName("char[20]")
and vfconvert.getType().hasName("char[20]")
and viplace.getType().hasName("int")
and vfplace.getType().hasName("int")
and vpadlen.getType().hasName("int")
and vzpadlen.getType().hasName("int")
and vsbuffer.getParentScope+() = func
and vbuffer.getParentScope+() = func
and vcurrlen.getParentScope+() = func
and vmaxlen.getParentScope+() = func
and vsignvalue.getParentScope+() = func
and viconvert.getParentScope+() = func
and vfconvert.getParentScope+() = func
and viplace.getParentScope+() = func
and vfplace.getParentScope+() = func
and vpadlen.getParentScope+() = func
and vzpadlen.getParentScope+() = func
select func, vsbuffer, vbuffer, vcurrlen, vmaxlen, vsignvalue, viconvert, vfconvert, viplace, vfplace, vpadlen, vzpadlen
