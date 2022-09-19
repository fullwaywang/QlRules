import cpp

predicate func_3(Variable vblksize) {
	exists(VariableAccess target_3 |
		target_3.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblksize)
}

predicate func_4(Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LTExpr).getType().hasName("int")
		and target_4.getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="512"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="512"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vstate, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="blksize"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="512"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vstate) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="blksize"
		and target_6.getType().hasName("int")
		and target_6.getQualifier().(VariableAccess).getTarget()=vstate)
}

from Function func, Variable vstate, Variable vblksize
where
not func_3(vblksize)
and not func_4(func)
and not func_5(vstate, func)
and func_6(vstate)
and vstate.getType().hasName("tftp_state_data_t *")
and vblksize.getType().hasName("int")
and vstate.getParentScope+() = func
and vblksize.getParentScope+() = func
select func, vstate, vblksize
