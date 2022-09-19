import cpp

predicate func_2(Variable vsctx, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("X509_STORE_CTX_cleanup")
		and target_2.getExpr().(FunctionCall).getType().hasName("void")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vstore, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("X509_STORE_set_flags")
		and target_3.getExpr().(FunctionCall).getType().hasName("int")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstore
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_6(Variable vret, Variable vi, Variable vsctx, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_6.getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_6.getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_6.getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_get_error")
		and target_6.getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_6.getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx
		and target_6.getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="24"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_8(Variable vret, Variable vi, Variable vsctx) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_get_error")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsctx
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="24")
}

predicate func_9(Function func) {
	exists(BlockStmt target_9 |
		target_9.getStmt(0) instanceof ExprStmt
		and target_9.getEnclosingFunction() = func
		and target_9.getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

from Function func, Variable vret, Variable vi, Variable vx, Variable vuntrusted, Variable vsctx, Variable vstore
where
not func_2(vsctx, func)
and not func_3(vstore, func)
and not func_6(vret, vi, vsctx, func)
and func_8(vret, vi, vsctx)
and func_9(func)
and vret.getType().hasName("int")
and vi.getType().hasName("int")
and vx.getType().hasName("X509 *")
and vuntrusted.getType().hasName("stack_st_X509 *")
and vsctx.getType().hasName("X509_STORE_CTX *")
and vstore.getType().hasName("X509_STORE *")
and vret.getParentScope+() = func
and vi.getParentScope+() = func
and vx.getParentScope+() = func
and vuntrusted.getParentScope+() = func
and vsctx.getParentScope+() = func
and vstore.getParentScope+() = func
select func, vret, vi, vx, vuntrusted, vsctx, vstore
