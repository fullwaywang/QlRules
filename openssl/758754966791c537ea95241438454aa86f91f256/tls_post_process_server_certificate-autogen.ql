import cpp

predicate func_0(Variable vi, Variable v__func__, Parameter vs) {
	exists(EQExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(VariableAccess).getTarget()=vi
		and target_0.getRightOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_0.getParent().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verify_mode"
		and target_0.getParent().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("uint32_t")
		and target_0.getParent().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getParent().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(FunctionCall).getTarget().hasName("ssl_x509err2alert")
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="verify_result"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="134"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

from Function func, Variable vi, Variable v__func__, Parameter vs
where
not func_0(vi, v__func__, vs)
and func_2(func)
and vi.getType().hasName("int")
and v__func__.getType().hasName("const char[36]")
and vs.getType().hasName("SSL *")
and vi.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vs.getParentScope+() = func
select func, vi, v__func__, vs
