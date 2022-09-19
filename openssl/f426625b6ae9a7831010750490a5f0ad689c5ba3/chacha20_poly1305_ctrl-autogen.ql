import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="509"
		and not target_0.getValue()="511"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="529"
		and not target_1.getValue()="531"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="16"
		and not target_2.getValue()="12"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter varg) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalOrExpr).getLeftOperand().(LEExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalOrExpr).getLeftOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=varg
		and target_3.getCondition().(LogicalOrExpr).getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalOrExpr).getRightOperand().(GTExpr).getType().hasName("int")
		and target_3.getCondition().(LogicalOrExpr).getRightOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=varg
		and target_3.getCondition().(LogicalOrExpr).getRightOperand().(GTExpr).getLesserOperand().(Literal).getValue()="12"
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_4(Parameter varg) {
	exists(LogicalOrExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLeftOperand().(LEExpr).getType().hasName("int")
		and target_4.getLeftOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=varg
		and target_4.getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getRightOperand().(GTExpr).getType().hasName("int")
		and target_4.getRightOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=varg
		and target_4.getRightOperand().(GTExpr).getLesserOperand().(Literal).getValue()="16"
		and target_4.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter varg
where
func_0(func)
and func_1(func)
and func_2(func)
and not func_3(varg)
and func_4(varg)
and varg.getType().hasName("int")
and varg.getParentScope+() = func
select func, varg
