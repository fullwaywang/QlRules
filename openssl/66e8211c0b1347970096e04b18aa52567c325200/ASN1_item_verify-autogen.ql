import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="146"
		and not target_0.getValue()="152"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="152"
		and not target_1.getValue()="158"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="161"
		and not target_2.getValue()="167"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="173"
		and not target_3.getValue()="179"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vpkey, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getType().hasName("int")
		and target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vpkey
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="197"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="3"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="a_verify.c"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="143"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Parameter vpkey
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_4(vpkey, func)
and vpkey.getType().hasName("EVP_PKEY *")
and vpkey.getParentScope+() = func
select func, vpkey
