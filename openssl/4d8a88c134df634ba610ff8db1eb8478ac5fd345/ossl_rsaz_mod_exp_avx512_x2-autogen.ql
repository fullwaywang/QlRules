import cpp

predicate func_0(Parameter vfactor_size, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignDivExpr).getType().hasName("int")
		and target_0.getExpr().(AssignDivExpr).getLValue().(VariableAccess).getTarget()=vfactor_size
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getType().hasName("unsigned long")
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getValue()="64"
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType().hasName("unsigned long")
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="8"
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vfactor_size
where
not func_0(vfactor_size, func)
and vfactor_size.getType().hasName("int")
and vfactor_size.getParentScope+() = func
select func, vfactor_size
