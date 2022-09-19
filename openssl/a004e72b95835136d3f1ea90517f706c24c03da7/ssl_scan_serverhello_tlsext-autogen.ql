import cpp

predicate func_0(Parameter vd, Parameter vn, Variable vdata) {
	exists(PointerDiffExpr target_0 |
		target_0.getType().hasName("long")
		and target_0.getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_0.getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_0.getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_0.getRightOperand().(VariableAccess).getTarget()=vdata
		and target_0.getParent().(LEExpr).getGreaterOperand().(Literal).getValue()="2")
}

predicate func_3(Parameter vd, Parameter vn, Variable vsize, Variable vdata) {
	exists(LTExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_3.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize)
}

predicate func_4(Parameter vd, Parameter vn) {
	exists(PointerAddExpr target_4 |
		target_4.getType().hasName("unsigned char *")
		and target_4.getLeftOperand().(VariableAccess).getTarget()=vd
		and target_4.getRightOperand().(VariableAccess).getTarget()=vn)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="2"
		and target_10.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="4"
		and target_13.getEnclosingFunction() = func)
}

predicate func_19(Variable vsize, Variable vdata, Function func) {
	exists(GTExpr target_19 |
		target_19.getType().hasName("int")
		and target_19.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_19.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_19.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_19.getLesserOperand() instanceof PointerAddExpr
		and target_19.getEnclosingFunction() = func)
}

from Function func, Parameter vd, Parameter vn, Parameter val, Variable vlength, Variable vsize, Variable vdata
where
not func_0(vd, vn, vdata)
and not func_3(vd, vn, vsize, vdata)
and func_4(vd, vn)
and func_10(func)
and func_13(func)
and func_19(vsize, vdata, func)
and vd.getType().hasName("unsigned char *")
and vn.getType().hasName("int")
and val.getType().hasName("int *")
and vlength.getType().hasName("unsigned short")
and vsize.getType().hasName("unsigned short")
and vdata.getType().hasName("unsigned char *")
and vd.getParentScope+() = func
and vn.getParentScope+() = func
and val.getParentScope+() = func
and vlength.getParentScope+() = func
and vsize.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vd, vn, val, vlength, vsize, vdata
