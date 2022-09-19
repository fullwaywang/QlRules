import cpp

predicate func_0(Parameter vh) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("char[257]")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_1(Parameter vh, Variable vhlen) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_1.getCondition().(LogicalOrExpr).getLeftOperand().(GTExpr).getType().hasName("int")
		and target_1.getCondition().(LogicalOrExpr).getLeftOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vhlen
		and target_1.getCondition().(LogicalOrExpr).getLeftOperand().(GTExpr).getLesserOperand().(Literal).getValue()="256"
		and target_1.getCondition().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_1.getCondition().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vhlen
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_2(Parameter vh, Parameter vhostname, Variable vhlen) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getType().hasName("void *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhostname
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhlen
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_3(Parameter vh, Parameter vhostname, Variable vhlen) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EQExpr).getType().hasName("int")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getType().hasName("char")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhostname
		and target_3.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getType().hasName("unsigned long")
		and target_3.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vhlen
		and target_3.getCondition().(EQExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(EQExpr).getRightOperand().(CharLiteral).getValue()="46"
		and target_3.getThen().(ExprStmt).getExpr().(PrefixDecrExpr).getType().hasName("size_t")
		and target_3.getThen().(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vhlen
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_4(Parameter vh, Variable vhlen) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getType().hasName("char")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getType().hasName("char")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vhlen
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_5(Parameter vh, Parameter vhostname) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getType().hasName("const char *")
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhostname
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vh)
}

predicate func_7(Function func) {
	exists(ReturnStmt target_7 |
		target_7.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
		and target_7.getEnclosingFunction() = func)
}

from Function func, Parameter vh, Parameter vhostname, Variable vhlen
where
not func_0(vh)
and not func_1(vh, vhlen)
and not func_2(vh, vhostname, vhlen)
and not func_3(vh, vhostname, vhlen)
and not func_4(vh, vhlen)
and not func_5(vh, vhostname)
and func_7(func)
and vh.getType().hasName("hsts *")
and vhostname.getType().hasName("const char *")
and vhlen.getType().hasName("size_t")
and vh.getParentScope+() = func
and vhostname.getParentScope+() = func
and vhlen.getParentScope+() = func
select func, vh, vhostname, vhlen
