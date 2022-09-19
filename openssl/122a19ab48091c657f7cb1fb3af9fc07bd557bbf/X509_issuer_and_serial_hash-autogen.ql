import cpp

predicate func_0(Variable vf, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EQExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vf
		and target_0.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vf
where
not func_0(vf, func)
and vf.getType().hasName("char *")
and vf.getParentScope+() = func
select func, vf
