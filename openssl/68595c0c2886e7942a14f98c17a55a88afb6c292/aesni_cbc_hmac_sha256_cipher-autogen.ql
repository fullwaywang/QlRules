import cpp

predicate func_0(Variable vmaxpad, Variable vpad, Variable vret, Variable vplen) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAndExpr).getType().hasName("int")
		and target_0.getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_0.getExpr().(AssignAndExpr).getRValue().(FunctionCall).getTarget().hasName("constant_time_ge")
		and target_0.getExpr().(AssignAndExpr).getRValue().(FunctionCall).getType().hasName("unsigned int")
		and target_0.getExpr().(AssignAndExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaxpad
		and target_0.getExpr().(AssignAndExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpad
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vplen
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getRightOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

from Function func, Variable vmaxpad, Variable vpad, Variable vret, Variable vplen
where
not func_0(vmaxpad, vpad, vret, vplen)
and vmaxpad.getType().hasName("unsigned int")
and vpad.getType().hasName("unsigned int")
and vret.getType().hasName("int")
and vplen.getType().hasName("size_t")
and vmaxpad.getParentScope+() = func
and vpad.getParentScope+() = func
and vret.getParentScope+() = func
and vplen.getParentScope+() = func
select func, vmaxpad, vpad, vret, vplen
