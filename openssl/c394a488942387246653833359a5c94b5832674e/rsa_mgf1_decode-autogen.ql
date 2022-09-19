import cpp

predicate func_0(Parameter valg) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=valg
		and target_0.getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="parameter"
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("ASN1_TYPE *")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valg
		and target_0.getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_1(Parameter valg) {
	exists(EQExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(VariableAccess).getTarget()=valg
		and target_1.getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter valg
where
not func_0(valg)
and func_1(valg)
and valg.getType().hasName("X509_ALGOR *")
and valg.getParentScope+() = func
select func, valg
