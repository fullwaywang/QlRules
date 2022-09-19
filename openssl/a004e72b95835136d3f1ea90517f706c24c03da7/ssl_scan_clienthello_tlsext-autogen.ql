import cpp

predicate func_0(Parameter vlimit, Variable vdata) {
	exists(LTExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_0.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_0.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_0.getGreaterOperand().(Literal).getValue()="2")
}

predicate func_1(Parameter vlimit, Variable vlen, Variable vdata) {
	exists(PointerDiffExpr target_1 |
		target_1.getType().hasName("long")
		and target_1.getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_1.getRightOperand().(VariableAccess).getTarget()=vdata
		and target_1.getParent().(NEExpr).getRightOperand().(VariableAccess).getTarget()=vlen)
}

predicate func_2(Parameter vlimit, Variable vdata) {
	exists(GEExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getGreaterOperand().(PointerDiffExpr).getType().hasName("long")
		and target_2.getGreaterOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_2.getGreaterOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_2.getLesserOperand().(Literal).getValue()="4")
}

predicate func_3(Parameter vlimit, Variable vsize, Variable vdata) {
	exists(LTExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_3.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize)
}

predicate func_7(Function func) {
	exists(VariableAccess target_7 |
		target_7.getParent().(GTExpr).getLesserOperand() instanceof PointerSubExpr
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="2"
		and target_8.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="4"
		and target_12.getEnclosingFunction() = func)
}

predicate func_16(Parameter vlimit, Variable vdata, Function func) {
	exists(GTExpr target_16 |
		target_16.getType().hasName("int")
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vdata
		and target_16.getLesserOperand().(PointerSubExpr).getType().hasName("unsigned char *")
		and target_16.getLesserOperand().(PointerSubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_16.getLesserOperand().(PointerSubExpr).getRightOperand() instanceof Literal
		and target_16.getEnclosingFunction() = func)
}

predicate func_18(Parameter vlimit, Variable vdata, Function func) {
	exists(LEExpr target_18 |
		target_18.getType().hasName("int")
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vdata
		and target_18.getGreaterOperand().(PointerSubExpr).getType().hasName("unsigned char *")
		and target_18.getGreaterOperand().(PointerSubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_18.getGreaterOperand().(PointerSubExpr).getRightOperand() instanceof Literal
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Parameter vlimit, Variable vsize, Variable vdata) {
	exists(GTExpr target_19 |
		target_19.getType().hasName("int")
		and target_19.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_19.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_19.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_19.getLesserOperand().(VariableAccess).getTarget()=vlimit)
}

from Function func, Parameter vlimit, Variable vsize, Variable vlen, Variable vdata
where
not func_0(vlimit, vdata)
and not func_1(vlimit, vlen, vdata)
and not func_2(vlimit, vdata)
and not func_3(vlimit, vsize, vdata)
and func_7(func)
and func_8(func)
and func_12(func)
and func_16(vlimit, vdata, func)
and func_18(vlimit, vdata, func)
and func_19(vlimit, vsize, vdata)
and vlimit.getType().hasName("unsigned char *")
and vsize.getType().hasName("unsigned short")
and vlen.getType().hasName("unsigned short")
and vdata.getType().hasName("unsigned char *")
and vlimit.getParentScope+() = func
and vsize.getParentScope+() = func
and vlen.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vlimit, vsize, vlen, vdata
