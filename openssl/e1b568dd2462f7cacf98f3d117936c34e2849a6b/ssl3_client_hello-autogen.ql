import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="773"
		and not target_0.getValue()="774"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="783"
		and not target_1.getValue()="784"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="794"
		and not target_2.getValue()="795"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="830"
		and not target_3.getValue()="831"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="837"
		and not target_4.getValue()="838"
		and target_4.getEnclosingFunction() = func)
}

predicate func_7(Parameter vs, Variable vp) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("ssl_fill_hello_random")
		and target_7.getType().hasName("int")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vs
		and target_7.getArgument(1).(Literal).getValue()="0"
		and target_7.getArgument(2).(VariableAccess).getTarget()=vp
		and target_7.getArgument(3).(SizeofExprOperator).getType().hasName("unsigned long")
		and target_7.getArgument(3).(SizeofExprOperator).getValue()="32"
		and target_7.getArgument(3).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="client_random"
		and target_7.getArgument(3).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getType().hasName("unsigned char[32]")
		and target_7.getArgument(3).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_7.getArgument(3).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ssl3_state_st *")
		and target_7.getArgument(3).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_8(Function func) {
	exists(VariableAccess target_8 |
		target_8.getParent().(IfStmt).getThen() instanceof ExprStmt
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Variable vi, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr() instanceof FunctionCall
		and target_9.getEnclosingFunction() = func
		and target_9.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vi)
}

from Function func, Parameter vs, Variable vp, Variable vi
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_7(vs, vp)
and func_8(func)
and func_9(vi, func)
and vs.getType().hasName("SSL *")
and vp.getType().hasName("unsigned char *")
and vi.getType().hasName("int")
and vs.getParentScope+() = func
and vp.getParentScope+() = func
and vi.getParentScope+() = func
select func, vs, vp, vi
