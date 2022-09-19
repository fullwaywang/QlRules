import cpp

predicate func_0(Parameter vlimit, Parameter vdata) {
	exists(LEExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_0.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_0.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_0.getGreaterOperand().(Literal).getValue()="2")
}

predicate func_1(Parameter vlimit, Parameter vdata) {
	exists(LTExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_1.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_1.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_1.getGreaterOperand().(Literal).getValue()="4")
}

predicate func_2(Parameter vlimit, Variable vsize, Parameter vdata) {
	exists(LTExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_2.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_2.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vsize)
}

predicate func_6(Variable vlen1, Parameter vdata) {
	exists(PointerAddExpr target_6 |
		target_6.getType().hasName("const unsigned char *")
		and target_6.getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_6.getRightOperand().(VariableAccess).getTarget()=vlen1)
}

predicate func_11(Function func) {
	exists(VariableAccess target_11 |
		target_11.getParent().(GEExpr).getLesserOperand() instanceof PointerSubExpr
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="2"
		and target_12.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="4"
		and target_14.getEnclosingFunction() = func)
}

predicate func_21(Parameter vlimit, Parameter vdata, Function func) {
	exists(GEExpr target_21 |
		target_21.getType().hasName("int")
		and target_21.getGreaterOperand().(VariableAccess).getTarget()=vdata
		and target_21.getLesserOperand().(PointerSubExpr).getType().hasName("const unsigned char *")
		and target_21.getLesserOperand().(PointerSubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_21.getLesserOperand().(PointerSubExpr).getRightOperand() instanceof Literal
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Parameter vlimit, Parameter vdata, Function func) {
	exists(GTExpr target_22 |
		target_22.getType().hasName("int")
		and target_22.getGreaterOperand().(VariableAccess).getTarget()=vdata
		and target_22.getLesserOperand().(PointerSubExpr).getType().hasName("const unsigned char *")
		and target_22.getLesserOperand().(PointerSubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_22.getLesserOperand().(PointerSubExpr).getRightOperand() instanceof Literal
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Parameter vlimit, Variable vsize, Parameter vdata) {
	exists(GTExpr target_23 |
		target_23.getType().hasName("int")
		and target_23.getGreaterOperand().(PointerAddExpr).getType().hasName("const unsigned char *")
		and target_23.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_23.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vlimit)
}

from Function func, Parameter vlimit, Variable vsize, Variable vlen1, Variable vlen2, Variable vlen, Parameter vdata
where
not func_0(vlimit, vdata)
and not func_1(vlimit, vdata)
and not func_2(vlimit, vsize, vdata)
and func_6(vlen1, vdata)
and func_11(func)
and func_12(func)
and func_14(func)
and func_21(vlimit, vdata, func)
and func_22(vlimit, vdata, func)
and func_23(vlimit, vsize, vdata)
and vlimit.getType().hasName("const unsigned char *")
and vsize.getType().hasName("unsigned short")
and vlen1.getType().hasName("const size_t")
and vlen2.getType().hasName("const size_t")
and vlen.getType().hasName("const size_t")
and vdata.getType().hasName("const unsigned char *")
and vlimit.getParentScope+() = func
and vsize.getParentScope+() = func
and vlen1.getParentScope+() = func
and vlen2.getParentScope+() = func
and vlen.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vlimit, vsize, vlen1, vlen2, vlen, vdata
