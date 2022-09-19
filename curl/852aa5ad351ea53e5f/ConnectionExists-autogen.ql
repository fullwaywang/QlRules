import cpp

predicate func_0(Parameter vneedle, Variable vcheck) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_0.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_safecmp")
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("bool")
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sasl_authzid"
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sasl_authzid"
		and target_0.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck
		and target_0.getRightOperand().(NotExpr).getType().hasName("int")
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Curl_safecmp")
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("bool")
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="oauth_bearer"
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck)
}

predicate func_1(Parameter vneedle, Variable vcheck) {
	exists(LogicalOrExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getLeftOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck
		and target_1.getRightOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getRightOperand().(FunctionCall).getType().hasName("int")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_1.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="passwd"
		and target_1.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcheck)
}

from Function func, Parameter vneedle, Variable vcheck
where
not func_0(vneedle, vcheck)
and func_1(vneedle, vcheck)
and vneedle.getType().hasName("connectdata *")
and vcheck.getType().hasName("connectdata *")
and vneedle.getParentScope+() = func
and vcheck.getParentScope+() = func
select func, vneedle, vcheck
