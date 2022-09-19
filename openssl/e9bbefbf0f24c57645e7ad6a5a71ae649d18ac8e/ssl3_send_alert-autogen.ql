import cpp

predicate func_0(Parameter vlevel, Parameter vs) {
	exists(BlockStmt target_0 |
		target_0.getStmt(0).(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_0.getStmt(0).(IfStmt).getCondition().(NEExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getStmt(0).(IfStmt).getCondition().(NEExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("SSL_SESSION *")
		and target_0.getStmt(0).(IfStmt).getCondition().(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt(0).(IfStmt).getCondition().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("int")
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_0.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getType().hasName("int")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="12293"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="5"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8192"
		and target_0.getParent().(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_0.getParent().(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vlevel
		and target_0.getParent().(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_3(Parameter vs, Function func) {
	exists(LogicalAndExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand() instanceof EQExpr
		and target_3.getRightOperand() instanceof NEExpr
		and target_3.getEnclosingFunction() = func
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getType().hasName("int")
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

from Function func, Parameter vlevel, Parameter vs
where
not func_0(vlevel, vs)
and func_3(vs, func)
and vlevel.getType().hasName("int")
and vs.getType().hasName("SSL *")
and vlevel.getParentScope+() = func
and vs.getParentScope+() = func
select func, vlevel, vs
