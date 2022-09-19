import cpp

predicate func_0(Parameter vneedle, Variable vcheck) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EQExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("get_protocol_family")
		and target_0.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getType().hasName("unsigned int")
		and target_0.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="handler"
		and target_0.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("const Curl_handler *")
		and target_0.getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getValue()="48"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getValue()="16"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getValue()="32"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(EQExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="5"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ssh_config_matches")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vneedle
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcheck)
}

from Function func, Parameter vneedle, Variable vcheck
where
not func_0(vneedle, vcheck)
and vneedle.getType().hasName("connectdata *")
and vcheck.getType().hasName("connectdata *")
and vneedle.getParentScope+() = func
and vcheck.getParentScope+() = func
select func, vneedle, vcheck
