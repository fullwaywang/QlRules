import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1315"
		and not target_0.getValue()="1316"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1346"
		and not target_1.getValue()="1347"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1433"
		and not target_2.getValue()="1434"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1466"
		and not target_3.getValue()="1467"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1477"
		and not target_4.getValue()="1478"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1501"
		and not target_5.getValue()="1502"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable valert_level, Parameter vs) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="12293"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="5"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getValue()="12288"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8192"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=valert_level
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="2")
}

from Function func, Variable valert_level, Parameter vs
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and not func_6(valert_level, vs)
and valert_level.getType().hasName("int")
and vs.getType().hasName("SSL *")
and valert_level.getParentScope+() = func
and vs.getParentScope+() = func
select func, valert_level, vs
