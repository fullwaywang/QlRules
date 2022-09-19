import cpp

predicate func_2(Parameter vlimit, Variable vp, Variable vi) {
	exists(LEExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_2.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_2.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_2.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_2.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_3(Parameter vlimit, Variable vp, Variable vi) {
	exists(LTExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_3.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_4(Parameter vlimit, Variable vp) {
	exists(LEExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_4.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_4.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_4.getGreaterOperand().(Literal).getValue()="2"
		and target_4.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_6(Parameter vlimit, Variable vp, Variable vsize) {
	exists(LTExpr target_6 |
		target_6.getType().hasName("int")
		and target_6.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_6.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_6.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vsize
		and target_6.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="2"
		and target_14.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="4"
		and target_17.getEnclosingFunction() = func)
}

predicate func_22(Parameter vlimit, Variable vp) {
	exists(GEExpr target_22 |
		target_22.getType().hasName("int")
		and target_22.getGreaterOperand().(VariableAccess).getTarget()=vp
		and target_22.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_22.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_22.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_22.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_23(Parameter vlimit, Variable vp) {
	exists(GTExpr target_23 |
		target_23.getType().hasName("int")
		and target_23.getGreaterOperand().(VariableAccess).getTarget()=vp
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_23.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_23.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_23.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_24(Parameter vlimit, Variable vp, Function func) {
	exists(GEExpr target_24 |
		target_24.getType().hasName("int")
		and target_24.getGreaterOperand().(PointerAddExpr).getType().hasName("const unsigned char *")
		and target_24.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_24.getGreaterOperand().(PointerAddExpr).getRightOperand() instanceof Literal
		and target_24.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_24.getEnclosingFunction() = func
		and target_24.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_26(Parameter vlimit, Variable vp, Variable vsize) {
	exists(GTExpr target_26 |
		target_26.getType().hasName("int")
		and target_26.getGreaterOperand().(PointerAddExpr).getType().hasName("const unsigned char *")
		and target_26.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_26.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_26.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_26.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vlimit, Variable vp, Variable vi, Variable vsize
where
not func_2(vlimit, vp, vi)
and not func_3(vlimit, vp, vi)
and not func_4(vlimit, vp)
and not func_6(vlimit, vp, vsize)
and func_14(func)
and func_17(func)
and func_22(vlimit, vp)
and func_23(vlimit, vp)
and func_24(vlimit, vp, func)
and func_26(vlimit, vp, vsize)
and vlimit.getType().hasName("const unsigned char *")
and vp.getType().hasName("const unsigned char *")
and vi.getType().hasName("unsigned short")
and vsize.getType().hasName("unsigned short")
and vlimit.getParentScope+() = func
and vp.getParentScope+() = func
and vi.getParentScope+() = func
and vsize.getParentScope+() = func
select func, vlimit, vp, vi, vsize
