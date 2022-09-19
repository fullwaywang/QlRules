import cpp

predicate func_1(Variable vctx, Variable vret) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("X509_STORE_CTX_get_error")
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getType().hasName("int")
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getType().hasName("int")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vctx) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("X509_STORE_CTX_get_error")
		and target_2.getType().hasName("int")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctx)
}

predicate func_3(Variable vret, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret
		and target_3.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_3.getEnclosingFunction() = func
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getType().hasName("int")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vret
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LEExpr).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vctx, Variable vret
where
not func_1(vctx, vret)
and func_2(vctx)
and func_3(vret, func)
and vctx.getType().hasName("X509_STORE_CTX *")
and vret.getType().hasName("int")
and vctx.getParentScope+() = func
and vret.getParentScope+() = func
select func, vctx, vret
