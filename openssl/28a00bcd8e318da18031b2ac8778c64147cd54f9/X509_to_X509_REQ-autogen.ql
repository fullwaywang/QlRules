import cpp

predicate func_0(Variable vpktmp, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EQExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vpktmp
		and target_0.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vpktmp
where
not func_0(vpktmp, func)
and vpktmp.getType().hasName("EVP_PKEY *")
and vpktmp.getParentScope+() = func
select func, vpktmp
