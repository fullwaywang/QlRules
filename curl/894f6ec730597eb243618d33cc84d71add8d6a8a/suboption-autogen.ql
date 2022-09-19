import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="%127[^,],%127s"
		and not target_0.getValue()="%127[^,]%1[,]%127s"
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Variable vtemp, Variable vlen, Variable vtmplen) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("char[2]")
		and target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(StringLiteral).getValue()=""
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LTExpr).getLesserOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LTExpr).getLesserOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vtmplen
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LTExpr).getGreaterOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LTExpr).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="6")
}

predicate func_4(Variable vvarval) {
	exists(AssignExpr target_4 |
		target_4.getType().hasName("char")
		and target_4.getLValue().(ArrayExpr).getType().hasName("char")
		and target_4.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvarval
		and target_4.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getRValue().(Literal).getValue()="0")
}

predicate func_5(Variable vv, Variable vvarname, Variable vvarval) {
	exists(AssignExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getRValue().(FunctionCall).getTarget().hasName("sscanf")
		and target_5.getRValue().(FunctionCall).getType().hasName("int")
		and target_5.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_5.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv
		and target_5.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%127[^,]%1[,]%127s"
		and target_5.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvarname
		and target_5.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarval)
}

predicate func_12(Variable vtemp, Variable vlen, Variable vvarname, Variable vvarval) {
	exists(IfStmt target_12 |
		target_12.getCondition().(GEExpr).getType().hasName("int")
		and target_12.getCondition().(GEExpr).getLesserOperand().(Literal).getValue()="2"
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getType().hasName("size_t")
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("curl_msnprintf")
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtemp
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%c%s%c%s"
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarname
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_12.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vvarval
		and target_12.getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_12.getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_13(Variable vtemp, Variable vlen, Variable vvarname, Variable vvarval) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("curl_msnprintf")
		and target_13.getType().hasName("int")
		and target_13.getArgument(0).(AddressOfExpr).getType().hasName("unsigned char *")
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getType().hasName("unsigned char")
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtemp
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen
		and target_13.getArgument(1).(SubExpr).getType().hasName("unsigned long")
		and target_13.getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getType().hasName("unsigned long")
		and target_13.getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="2048"
		and target_13.getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp
		and target_13.getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen
		and target_13.getArgument(2).(StringLiteral).getValue()="%c%s%c%s"
		and target_13.getArgument(3).(Literal).getValue()="0"
		and target_13.getArgument(4).(VariableAccess).getTarget()=vvarname
		and target_13.getArgument(5).(Literal).getValue()="1"
		and target_13.getArgument(6).(VariableAccess).getTarget()=vvarval)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="2"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Variable vv, Variable vlen, Variable vvarname, Variable vvarval, Variable vtmplen, Function func) {
	exists(BlockStmt target_16 |
		target_16.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getType().hasName("size_t")
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vtmplen
		and target_16.getEnclosingFunction() = func
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvarname
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvarval
		and target_16.getParent().(IfStmt).getCondition().(EQExpr).getRightOperand() instanceof Literal)
}

from Function func, Variable vv, Variable vtemp, Variable vlen, Variable vvarname, Variable vvarval, Variable vtmplen
where
func_0(func)
and not func_3(vtemp, vlen, vtmplen)
and not func_4(vvarval)
and not func_5(vv, vvarname, vvarval)
and not func_12(vtemp, vlen, vvarname, vvarval)
and func_13(vtemp, vlen, vvarname, vvarval)
and func_15(func)
and func_16(vv, vlen, vvarname, vvarval, vtmplen, func)
and vv.getType().hasName("curl_slist *")
and vtemp.getType().hasName("unsigned char[2048]")
and vlen.getType().hasName("size_t")
and vvarname.getType().hasName("char[128]")
and vvarval.getType().hasName("char[128]")
and vtmplen.getType().hasName("size_t")
and vv.getParentScope+() = func
and vtemp.getParentScope+() = func
and vlen.getParentScope+() = func
and vvarname.getParentScope+() = func
and vvarval.getParentScope+() = func
and vtmplen.getParentScope+() = func
select func, vv, vtemp, vlen, vvarname, vvarval, vtmplen
