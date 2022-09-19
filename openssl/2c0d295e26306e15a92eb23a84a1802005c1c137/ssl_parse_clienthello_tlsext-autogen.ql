import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1412"
		and not target_0.getValue()="1422"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vs) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sk_pop_free")
		and target_1.getExpr().(FunctionCall).getType().hasName("void")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_OCSP_RESPID *")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getType().hasName("stack_st_OCSP_RESPID *")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_1.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getType().hasName("..(*)(..)")
		and target_1.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tlsext_status_type"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_2(Parameter vs, Parameter val, Variable vdsize) {
	exists(IfStmt target_2 |
		target_2.getCondition().(GTExpr).getType().hasName("int")
		and target_2.getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vdsize
		and target_2.getCondition().(GTExpr).getLesserOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("stack_st_OCSP_RESPID *")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sk_new_null")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_2.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("stack_st_OCSP_RESPID *")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tlsext_status_type"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_7(Parameter vs, Parameter val, Variable vsize, Variable vdata, Variable vsdata, Variable vdsize, Variable vid, Variable vidsize) {
	exists(BlockStmt target_7 |
		target_7.getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("OCSP_RESPID *")
		and target_7.getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_7.getStmt(2).(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_7.getStmt(2).(IfStmt).getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdsize
		and target_7.getStmt(2).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="4"
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getType().hasName("unsigned char *")
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getType().hasName("int")
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vidsize
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="8"
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getType().hasName("unsigned char *")
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(3).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_7.getStmt(4).(ExprStmt).getExpr().(AssignSubExpr).getType().hasName("int")
		and target_7.getStmt(4).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vdsize
		and target_7.getStmt(4).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getType().hasName("int")
		and target_7.getStmt(4).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getLeftOperand().(Literal).getValue()="2"
		and target_7.getStmt(4).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vidsize
		and target_7.getStmt(5).(ExprStmt).getExpr().(AssignSubExpr).getType().hasName("unsigned short")
		and target_7.getStmt(5).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vsize
		and target_7.getStmt(5).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getType().hasName("int")
		and target_7.getStmt(5).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getLeftOperand().(Literal).getValue()="2"
		and target_7.getStmt(5).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vidsize
		and target_7.getStmt(6).(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_7.getStmt(6).(IfStmt).getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdsize
		and target_7.getStmt(6).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getType().hasName("const unsigned char *")
		and target_7.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsdata
		and target_7.getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getType().hasName("unsigned char *")
		and target_7.getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(8).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vidsize
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getType().hasName("OCSP_RESPID *")
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vid
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("d2i_OCSP_RESPID")
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("OCSP_RESPID *")
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsdata
		and target_7.getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vidsize
		and target_7.getStmt(10).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_7.getStmt(10).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vid
		and target_7.getStmt(11).(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_7.getStmt(11).(IfStmt).getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_7.getStmt(11).(IfStmt).getCondition().(NEExpr).getRightOperand().(VariableAccess).getTarget()=vsdata
		and target_7.getStmt(11).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_7.getStmt(11).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sk_push")
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vid
		and target_7.getStmt(12).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_7.getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid
		and target_7.getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val
		and target_7.getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_7.getStmt(12).(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getParent().(WhileStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_7.getParent().(WhileStmt).getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vdsize
		and target_7.getParent().(WhileStmt).getCondition().(GTExpr).getLesserOperand().(Literal).getValue()="0")
}

predicate func_10(Variable vdsize) {
	exists(GTExpr target_10 |
		target_10.getType().hasName("int")
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vdsize
		and target_10.getLesserOperand().(Literal).getValue()="0")
}

predicate func_11(Function func) {
	exists(DeclStmt target_11 |
		target_11.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("OCSP_RESPID *")
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(DeclStmt target_12 |
		target_12.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Variable vdsize) {
	exists(IfStmt target_13 |
		target_13.getCondition().(LTExpr).getType().hasName("int")
		and target_13.getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdsize
		and target_13.getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="4")
}

predicate func_14(Variable vdata, Variable vidsize) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(CommaExpr).getType().hasName("unsigned char *")
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getType().hasName("int")
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vidsize
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getType().hasName("unsigned int")
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="8"
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata
		and target_14.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_14.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getType().hasName("unsigned char *")
		and target_14.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata
		and target_14.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2")
}

predicate func_15(Variable vdsize, Variable vidsize) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignSubExpr).getType().hasName("int")
		and target_15.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vdsize
		and target_15.getExpr().(AssignSubExpr).getRValue().(AddExpr).getType().hasName("int")
		and target_15.getExpr().(AssignSubExpr).getRValue().(AddExpr).getLeftOperand().(Literal).getValue()="2"
		and target_15.getExpr().(AssignSubExpr).getRValue().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vidsize)
}

predicate func_16(Variable vsize, Variable vidsize) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignSubExpr).getType().hasName("unsigned short")
		and target_16.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vsize
		and target_16.getExpr().(AssignSubExpr).getRValue().(AddExpr).getType().hasName("int")
		and target_16.getExpr().(AssignSubExpr).getRValue().(AddExpr).getLeftOperand().(Literal).getValue()="2"
		and target_16.getExpr().(AssignSubExpr).getRValue().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vidsize)
}

predicate func_17(Variable vdsize) {
	exists(IfStmt target_17 |
		target_17.getCondition().(LTExpr).getType().hasName("int")
		and target_17.getCondition().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vdsize
		and target_17.getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_18(Variable vdata, Variable vsdata) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(AssignExpr).getType().hasName("const unsigned char *")
		and target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsdata
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata)
}

predicate func_19(Variable vdata, Variable vidsize) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(AssignPointerAddExpr).getType().hasName("unsigned char *")
		and target_19.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata
		and target_19.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vidsize)
}

predicate func_20(Variable vsdata, Variable vid, Variable vidsize) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(AssignExpr).getType().hasName("OCSP_RESPID *")
		and target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vid
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("d2i_OCSP_RESPID")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("OCSP_RESPID *")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getType().hasName("const unsigned char **")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsdata
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vidsize)
}

predicate func_21(Variable vid) {
	exists(IfStmt target_21 |
		target_21.getCondition().(NotExpr).getType().hasName("int")
		and target_21.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vid)
}

predicate func_22(Variable vdata, Variable vsdata, Variable vid) {
	exists(IfStmt target_22 |
		target_22.getCondition().(NEExpr).getType().hasName("int")
		and target_22.getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_22.getCondition().(NEExpr).getRightOperand().(VariableAccess).getTarget()=vsdata
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid)
}

predicate func_23(Parameter vs) {
	exists(PointerFieldAccess target_23 |
		target_23.getTarget().getName()="tlsext_ocsp_ids"
		and target_23.getType().hasName("stack_st_OCSP_RESPID *")
		and target_23.getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_24(Parameter vs) {
	exists(AssignExpr target_24 |
		target_24.getType().hasName("stack_st_OCSP_RESPID *")
		and target_24.getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_24.getLValue().(PointerFieldAccess).getType().hasName("stack_st_OCSP_RESPID *")
		and target_24.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_24.getRValue().(FunctionCall).getTarget().hasName("sk_new_null"))
}

predicate func_25(Parameter vs, Parameter val, Variable vid) {
	exists(IfStmt target_25 |
		target_25.getCondition().(NotExpr).getType().hasName("int")
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sk_push")
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_OCSP_RESPID *")
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getType().hasName("OCSP_RESPID *")
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vid
		and target_25.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid
		and target_25.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_25.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val
		and target_25.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_25.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_26(Parameter val, Variable vid, Function func) {
	exists(LogicalAndExpr target_26 |
		target_26.getType().hasName("int")
		and target_26.getLeftOperand().(NotExpr).getType().hasName("int")
		and target_26.getLeftOperand().(NotExpr).getOperand() instanceof PointerFieldAccess
		and target_26.getRightOperand().(NotExpr).getType().hasName("int")
		and target_26.getRightOperand().(NotExpr).getOperand() instanceof AssignExpr
		and target_26.getEnclosingFunction() = func
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_26.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vs, Parameter val, Variable vsize, Variable vdata, Variable vsdata, Variable vdsize, Variable vid, Variable vidsize
where
func_0(func)
and not func_1(vs)
and not func_2(vs, val, vdsize)
and not func_7(vs, val, vsize, vdata, vsdata, vdsize, vid, vidsize)
and func_10(vdsize)
and func_11(func)
and func_12(func)
and func_13(vdsize)
and func_14(vdata, vidsize)
and func_15(vdsize, vidsize)
and func_16(vsize, vidsize)
and func_17(vdsize)
and func_18(vdata, vsdata)
and func_19(vdata, vidsize)
and func_20(vsdata, vid, vidsize)
and func_21(vid)
and func_22(vdata, vsdata, vid)
and func_23(vs)
and func_24(vs)
and func_25(vs, val, vid)
and func_26(val, vid, func)
and vs.getType().hasName("SSL *")
and val.getType().hasName("int *")
and vsize.getType().hasName("unsigned short")
and vdata.getType().hasName("unsigned char *")
and vsdata.getType().hasName("const unsigned char *")
and vdsize.getType().hasName("int")
and vid.getType().hasName("OCSP_RESPID *")
and vidsize.getType().hasName("int")
and vs.getParentScope+() = func
and val.getParentScope+() = func
and vsize.getParentScope+() = func
and vdata.getParentScope+() = func
and vsdata.getParentScope+() = func
and vdsize.getParentScope+() = func
and vid.getParentScope+() = func
and vidsize.getParentScope+() = func
select func, vs, val, vsize, vdata, vsdata, vdsize, vid, vidsize
