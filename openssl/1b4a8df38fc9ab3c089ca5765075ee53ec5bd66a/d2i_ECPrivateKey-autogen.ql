import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1029"
		and not target_0.getValue()="1027"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1040"
		and not target_1.getValue()="1038"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1044"
		and not target_2.getValue()="1042"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1056"
		and not target_3.getValue()="1054"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1065"
		and not target_4.getValue()="1063"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter va, Variable vret) {
	exists(LogicalAndExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLeftOperand().(VariableAccess).getTarget()=vret
		and target_5.getRightOperand().(LogicalOrExpr).getType().hasName("int")
		and target_5.getRightOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_5.getRightOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=va
		and target_5.getRightOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_5.getRightOperand().(LogicalOrExpr).getRightOperand().(NEExpr).getType().hasName("int")
		and target_5.getRightOperand().(LogicalOrExpr).getRightOperand().(NEExpr).getLeftOperand().(PointerDereferenceExpr).getType().hasName("EC_KEY *")
		and target_5.getRightOperand().(LogicalOrExpr).getRightOperand().(NEExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va
		and target_5.getRightOperand().(LogicalOrExpr).getRightOperand().(NEExpr).getRightOperand().(VariableAccess).getTarget()=vret
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("EC_KEY_free")
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret)
}

predicate func_6(Parameter va, Variable vret) {
	exists(IfStmt target_6 |
		target_6.getCondition().(VariableAccess).getTarget()=va
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getType().hasName("EC_KEY *")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getType().hasName("EC_KEY *")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=va
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=va
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0")
}

predicate func_7(Variable vret) {
	exists(VariableAccess target_7 |
		target_7.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("EC_KEY_free")
		and target_7.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_7.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret)
}

from Function func, Parameter va, Variable vret
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and not func_5(va, vret)
and func_6(va, vret)
and func_7(vret)
and va.getType().hasName("EC_KEY **")
and vret.getType().hasName("EC_KEY *")
and va.getParentScope+() = func
and vret.getParentScope+() = func
select func, va, vret
