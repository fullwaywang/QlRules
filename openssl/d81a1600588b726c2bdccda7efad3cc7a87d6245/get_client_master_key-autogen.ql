import cpp

predicate func_0(Parameter vs, Variable vcp) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vcp
		and target_0.getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getRightOperand().(LTExpr).getType().hasName("int")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sk_find")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getType().hasName("stack_st_SSL_CIPHER *")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="ciphers"
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getType().hasName("const SSL_CIPHER *")
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vcp
		and target_0.getRightOperand().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="185"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s2_srvr.c"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="407"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_1(Parameter vs, Variable vcp) {
	exists(EQExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(VariableAccess).getTarget()=vcp
		and target_1.getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="107"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="185"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s2_srvr.c"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="407"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

from Function func, Parameter vs, Variable vcp
where
not func_0(vs, vcp)
and func_1(vs, vcp)
and vs.getType().hasName("SSL *")
and vcp.getType().hasName("const SSL_CIPHER *")
and vs.getParentScope+() = func
and vcp.getParentScope+() = func
select func, vs, vcp
