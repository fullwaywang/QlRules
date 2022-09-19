import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="685"
		and not target_0.getValue()="726"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="689"
		and not target_1.getValue()="730"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="690"
		and not target_2.getValue()="731"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="691"
		and not target_3.getValue()="732"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="695"
		and not target_4.getValue()="736"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="696"
		and not target_5.getValue()="737"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="697"
		and not target_6.getValue()="738"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="698"
		and not target_7.getValue()="739"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="699"
		and not target_8.getValue()="740"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="717"
		and not target_9.getValue()="758"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="725"
		and not target_10.getValue()="766"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="734"
		and not target_11.getValue()="775"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="744"
		and not target_12.getValue()="785"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="754"
		and not target_13.getValue()="795"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="773"
		and not target_14.getValue()="818"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="784"
		and not target_15.getValue()="829"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Variable vpublic, Variable vprivate, Variable vmaster, Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition().(NotExpr).getType().hasName("int")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_true")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/drbgtest.c"
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="800"
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="test_drbg_reseed_after_fork(master, public, private)"
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getType().hasName("int")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getLeftOperand().(FunctionCall).getTarget().hasName("test_drbg_reseed_after_fork")
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaster
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpublic
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprivate
		and target_16.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(NEExpr).getRightOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16)
}

from Function func, Variable vpublic, Variable vprivate, Variable vmaster
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(func)
and func_14(func)
and func_15(func)
and not func_16(vpublic, vprivate, vmaster, func)
and vpublic.getType().hasName("RAND_DRBG *")
and vprivate.getType().hasName("RAND_DRBG *")
and vmaster.getType().hasName("RAND_DRBG *")
and vpublic.getParentScope+() = func
and vprivate.getParentScope+() = func
and vmaster.getParentScope+() = func
select func, vpublic, vprivate, vmaster
