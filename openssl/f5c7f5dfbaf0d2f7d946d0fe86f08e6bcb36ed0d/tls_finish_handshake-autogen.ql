import cpp

predicate func_0(Parameter vs) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dtls1_clear_received_buffer")
		and target_0.getExpr().(FunctionCall).getType().hasName("void")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getType().hasName("unsigned int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="enc_flags"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl3_enc"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

from Function func, Parameter vs
where
not func_0(vs)
and vs.getType().hasName("SSL *")
and vs.getParentScope+() = func
select func, vs
