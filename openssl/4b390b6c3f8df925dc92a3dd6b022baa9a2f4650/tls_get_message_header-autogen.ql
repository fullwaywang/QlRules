import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="7"
		and not target_0.getValue()="152"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="418"
		and not target_1.getValue()="426"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="430"
		and not target_2.getValue()="426"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vs) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="init_buf"
		and target_3.getType().hasName("BUF_MEM *")
		and target_3.getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_4(Parameter vs, Variable vp, Variable vl) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(CommaExpr).getType().hasName("unsigned char *")
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getType().hasName("unsigned long")
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getType().hasName("unsigned long")
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="16"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="8"
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp
		and target_4.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getType().hasName("unsigned char *")
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp
		and target_4.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_6(Parameter vs, Variable vl) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getType().hasName("unsigned long")
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("unsigned long")
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("struct <unnamed>")
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vl
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_7(Parameter vs) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getType().hasName("void *")
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="init_msg"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("void *")
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getType().hasName("char *")
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("char *")
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_7.getExpr().(AssignExpr).getRValue().(PointerAddExpr).getRightOperand().(Literal).getValue()="4"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_8(Parameter vs) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="init_num"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_9(Parameter vs, Variable vl, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("size_t")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem_lib.c"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_9.getEnclosingFunction() = func
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_11(Parameter vs, Variable val, Variable vl, Function func) {
	exists(BlockStmt target_11 |
		target_11.getStmt(0) instanceof ExprStmt
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getType().hasName("int")
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vl
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getType().hasName("int")
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getValue()="2147483643"
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_11.getStmt(1).(IfStmt).getCondition().(GTExpr).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="47"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem_lib.c"
		and target_11.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vl
		and target_11.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getRightOperand().(Literal).getValue()="4"
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem_lib.c"
		and target_11.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="435"
		and target_11.getStmt(3) instanceof ExprStmt
		and target_11.getStmt(4) instanceof ExprStmt
		and target_11.getStmt(5) instanceof ExprStmt
		and target_11.getEnclosingFunction() = func
		and target_11.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("RECORD_LAYER_is_sslv2_record")
		and target_11.getParent().(IfStmt).getCondition().(FunctionCall).getType().hasName("int")
		and target_11.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("RECORD_LAYER *")
		and target_11.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_11.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_12(Function func) {
	exists(LabelStmt target_12 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

from Function func, Parameter vs, Variable val, Variable vp, Variable vl
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(vs)
and func_4(vs, vp, vl)
and func_6(vs, vl)
and func_7(vs)
and func_8(vs)
and func_9(vs, vl, func)
and func_11(vs, val, vl, func)
and func_12(func)
and vs.getType().hasName("SSL *")
and val.getType().hasName("int")
and vp.getType().hasName("unsigned char *")
and vl.getType().hasName("unsigned long")
and vs.getParentScope+() = func
and val.getParentScope+() = func
and vp.getParentScope+() = func
and vl.getParentScope+() = func
select func, vs, val, vp, vl
