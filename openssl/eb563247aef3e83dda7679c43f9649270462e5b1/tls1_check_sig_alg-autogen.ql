import cpp

predicate func_0(Variable vsigalg, Variable vsig_nid) {
	exists(LogicalAndExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(NEExpr).getType().hasName("int")
		and target_0.getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vsigalg
		and target_0.getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vsig_nid
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sigandhash"
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getType().hasName("int")
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsigalg
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_1(Variable vsigalg, Variable vsig_nid) {
	exists(EQExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(VariableAccess).getTarget()=vsig_nid
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="sigandhash"
		and target_1.getRightOperand().(PointerFieldAccess).getType().hasName("int")
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsigalg
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

from Function func, Variable vsigalg, Variable vsig_nid
where
not func_0(vsigalg, vsig_nid)
and func_1(vsigalg, vsig_nid)
and vsigalg.getType().hasName("const SIGALG_LOOKUP *")
and vsig_nid.getType().hasName("int")
and vsigalg.getParentScope+() = func
and vsig_nid.getParentScope+() = func
select func, vsigalg, vsig_nid
