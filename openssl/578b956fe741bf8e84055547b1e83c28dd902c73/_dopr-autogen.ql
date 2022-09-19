import cpp

predicate func_0(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vch, Variable vcurrlen) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vch
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="10"
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vch, Variable vvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vch
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="111"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(Literal).getValue()="8"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vch
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="117"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="10"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(ConditionalExpr).getElse().(Literal).getValue()="16"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vfvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getType().hasName("int")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtfp")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfvalue
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmin
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmax
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vflags
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Parameter vargs, Variable vcurrlen) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(BuiltInVarArg).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(BuiltInVarArg).getVAList().(VariableAccess).getTarget()=vargs
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vstrvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getType().hasName("int")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtstr")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrvalue
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vflags
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_5.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_6(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getType().hasName("int")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="16"
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(BitwiseOrExpr).getType().hasName("int")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(BitwiseOrExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="3"
		and target_6.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_8(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vcurrlen) {
	exists(IfStmt target_8 |
		target_8.getCondition().(NotExpr).getType().hasName("int")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcurrlen
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(CharLiteral).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_10(Variable vcurrlen) {
	exists(AddressOfExpr target_10 |
		target_10.getType().hasName("size_t *")
		and target_10.getOperand().(VariableAccess).getTarget()=vcurrlen)
}

predicate func_13(Variable vch) {
	exists(ConditionalExpr target_13 |
		target_13.getType().hasName("int")
		and target_13.getCondition().(EQExpr).getType().hasName("int")
		and target_13.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vch
		and target_13.getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="111"
		and target_13.getThen().(Literal).getValue()="8"
		and target_13.getElse().(ConditionalExpr).getType().hasName("int")
		and target_13.getElse().(ConditionalExpr).getCondition().(EQExpr).getType().hasName("int")
		and target_13.getElse().(ConditionalExpr).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vch
		and target_13.getElse().(ConditionalExpr).getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="117"
		and target_13.getElse().(ConditionalExpr).getThen().(Literal).getValue()="10"
		and target_13.getElse().(ConditionalExpr).getElse().(Literal).getValue()="16")
}

predicate func_16(Parameter vargs) {
	exists(BuiltInVarArg target_16 |
		target_16.getType().hasName("int")
		and target_16.getVAList().(VariableAccess).getTarget()=vargs)
}

predicate func_19(Variable vflags) {
	exists(BitwiseOrExpr target_19 |
		target_19.getType().hasName("int")
		and target_19.getLeftOperand().(VariableAccess).getTarget()=vflags
		and target_19.getRightOperand().(LShiftExpr).getType().hasName("int")
		and target_19.getRightOperand().(LShiftExpr).getValue()="8"
		and target_19.getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_19.getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="3")
}

predicate func_30(Function func) {
	exists(Literal target_30 |
		target_30.getValue()="10"
		and target_30.getEnclosingFunction() = func)
}

predicate func_62(Function func) {
	exists(Literal target_62 |
		target_62.getValue()="16"
		and target_62.getEnclosingFunction() = func)
}

predicate func_72(Function func) {
	exists(CharLiteral target_72 |
		target_72.getValue()="0"
		and target_72.getEnclosingFunction() = func)
}

predicate func_73(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vch, Function func) {
	exists(ExprStmt target_73 |
		target_73.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_73.getExpr().(FunctionCall).getType().hasName("void")
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_73.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_73.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_73.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_73.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vch
		and target_73.getEnclosingFunction() = func)
}

predicate func_74(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vvalue, Variable vmin, Variable vmax, Variable vflags, Function func) {
	exists(ExprStmt target_74 |
		target_74.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_74.getExpr().(FunctionCall).getType().hasName("void")
		and target_74.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_74.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_74.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_74.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_74.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_74.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_74.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_74.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_74.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags
		and target_74.getEnclosingFunction() = func)
}

predicate func_75(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vvalue, Variable vmin, Variable vmax, Variable vflags, Function func) {
	exists(ExprStmt target_75 |
		target_75.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_75.getExpr().(FunctionCall).getType().hasName("void")
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_75.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_75.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_75.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_75.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_75.getExpr().(FunctionCall).getArgument(5) instanceof ConditionalExpr
		and target_75.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_75.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_75.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags
		and target_75.getEnclosingFunction() = func)
}

predicate func_76(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vfvalue, Variable vmin, Variable vmax, Variable vflags, Function func) {
	exists(ExprStmt target_76 |
		target_76.getExpr().(FunctionCall).getTarget().hasName("fmtfp")
		and target_76.getExpr().(FunctionCall).getType().hasName("void")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_76.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_76.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_76.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_76.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfvalue
		and target_76.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmin
		and target_76.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmax
		and target_76.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vflags
		and target_76.getEnclosingFunction() = func)
}

predicate func_77(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_77 |
		target_77.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_77.getExpr().(FunctionCall).getType().hasName("void")
		and target_77.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_77.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_77.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_77.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_77.getExpr().(FunctionCall).getArgument(4) instanceof BuiltInVarArg
		and target_77.getEnclosingFunction() = func)
}

predicate func_78(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vstrvalue, Variable vmin, Variable vmax, Variable vflags, Function func) {
	exists(ExprStmt target_78 |
		target_78.getExpr().(FunctionCall).getTarget().hasName("fmtstr")
		and target_78.getExpr().(FunctionCall).getType().hasName("void")
		and target_78.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_78.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_78.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_78.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_78.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrvalue
		and target_78.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vflags
		and target_78.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_78.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_78.getEnclosingFunction() = func)
}

predicate func_79(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Variable vvalue, Variable vmin, Variable vmax, Function func) {
	exists(ExprStmt target_79 |
		target_79.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_79.getExpr().(FunctionCall).getType().hasName("void")
		and target_79.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_79.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_79.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_79.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_79.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue
		and target_79.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_79.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin
		and target_79.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax
		and target_79.getExpr().(FunctionCall).getArgument(8) instanceof BitwiseOrExpr
		and target_79.getEnclosingFunction() = func)
}

predicate func_81(Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Function func) {
	exists(ExprStmt target_81 |
		target_81.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_81.getExpr().(FunctionCall).getType().hasName("void")
		and target_81.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer
		and target_81.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer
		and target_81.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_81.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen
		and target_81.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_81.getEnclosingFunction() = func)
}

from Function func, Parameter vsbuffer, Parameter vbuffer, Parameter vmaxlen, Parameter vargs, Variable vch, Variable vvalue, Variable vfvalue, Variable vstrvalue, Variable vmin, Variable vmax, Variable vflags, Variable vcurrlen
where
not func_0(vsbuffer, vbuffer, vmaxlen, vch, vcurrlen)
and not func_1(vsbuffer, vbuffer, vmaxlen, vvalue, vmin, vmax, vflags, vcurrlen)
and not func_2(vsbuffer, vbuffer, vmaxlen, vch, vvalue, vmin, vmax, vflags, vcurrlen)
and not func_3(vsbuffer, vbuffer, vmaxlen, vfvalue, vmin, vmax, vflags, vcurrlen)
and not func_4(vsbuffer, vbuffer, vmaxlen, vargs, vcurrlen)
and not func_5(vsbuffer, vbuffer, vmaxlen, vstrvalue, vmin, vmax, vflags, vcurrlen)
and not func_6(vsbuffer, vbuffer, vmaxlen, vvalue, vmin, vmax, vflags, vcurrlen)
and not func_8(vsbuffer, vbuffer, vmaxlen, vcurrlen)
and func_10(vcurrlen)
and func_13(vch)
and func_16(vargs)
and func_19(vflags)
and func_30(func)
and func_62(func)
and func_72(func)
and func_73(vsbuffer, vbuffer, vmaxlen, vch, func)
and func_74(vsbuffer, vbuffer, vmaxlen, vvalue, vmin, vmax, vflags, func)
and func_75(vsbuffer, vbuffer, vmaxlen, vvalue, vmin, vmax, vflags, func)
and func_76(vsbuffer, vbuffer, vmaxlen, vfvalue, vmin, vmax, vflags, func)
and func_77(vsbuffer, vbuffer, vmaxlen, func)
and func_78(vsbuffer, vbuffer, vmaxlen, vstrvalue, vmin, vmax, vflags, func)
and func_79(vsbuffer, vbuffer, vmaxlen, vvalue, vmin, vmax, func)
and func_81(vsbuffer, vbuffer, vmaxlen, func)
and vsbuffer.getType().hasName("char **")
and vbuffer.getType().hasName("char **")
and vmaxlen.getType().hasName("size_t *")
and vargs.getType().hasName("va_list")
and vch.getType().hasName("char")
and vvalue.getType().hasName("long")
and vfvalue.getType().hasName("double")
and vstrvalue.getType().hasName("char *")
and vmin.getType().hasName("int")
and vmax.getType().hasName("int")
and vflags.getType().hasName("int")
and vcurrlen.getType().hasName("size_t")
and vsbuffer.getParentScope+() = func
and vbuffer.getParentScope+() = func
and vmaxlen.getParentScope+() = func
and vargs.getParentScope+() = func
and vch.getParentScope+() = func
and vvalue.getParentScope+() = func
and vfvalue.getParentScope+() = func
and vstrvalue.getParentScope+() = func
and vmin.getParentScope+() = func
and vmax.getParentScope+() = func
and vflags.getParentScope+() = func
and vcurrlen.getParentScope+() = func
select func, vsbuffer, vbuffer, vmaxlen, vargs, vch, vvalue, vfvalue, vstrvalue, vmin, vmax, vflags, vcurrlen
