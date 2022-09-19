import cpp

predicate func_0(Parameter vdata, Parameter vlimit) {
	exists(PointerDiffExpr target_0 |
		target_0.getType().hasName("long")
		and target_0.getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_0.getRightOperand().(VariableAccess).getTarget()=vdata
		and target_0.getParent().(LEExpr).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getParent().(LEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_1(Parameter vdata, Parameter vlimit, Variable vlen) {
	exists(LTExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_1.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_1.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vlen
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_3(Parameter vdata, Parameter vlimit, Variable vsize) {
	exists(LTExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_3.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vdata
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
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

predicate func_17(Parameter vdata, Parameter vlimit, Variable vlen) {
	exists(GTExpr target_17 |
		target_17.getType().hasName("int")
		and target_17.getGreaterOperand().(VariableAccess).getTarget()=vdata
		and target_17.getLesserOperand().(PointerSubExpr).getType().hasName("const unsigned char *")
		and target_17.getLesserOperand().(PointerSubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_17.getLesserOperand().(PointerSubExpr).getRightOperand().(VariableAccess).getTarget()=vlen
		and target_17.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_19(Parameter vdata, Parameter vlimit, Variable vsize) {
	exists(GTExpr target_19 |
		target_19.getType().hasName("int")
		and target_19.getGreaterOperand().(PointerAddExpr).getType().hasName("const unsigned char *")
		and target_19.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vdata
		and target_19.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_19.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_19.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

from Function func, Parameter vdata, Parameter vlimit, Variable vsize, Variable vlen
where
not func_0(vdata, vlimit)
and not func_1(vdata, vlimit, vlen)
and not func_3(vdata, vlimit, vsize)
and func_8(func)
and func_12(func)
and func_17(vdata, vlimit, vlen)
and func_19(vdata, vlimit, vsize)
and vdata.getType().hasName("const unsigned char *")
and vlimit.getType().hasName("const unsigned char *")
and vsize.getType().hasName("unsigned short")
and vlen.getType().hasName("unsigned short")
and vdata.getParentScope+() = func
and vlimit.getParentScope+() = func
and vsize.getParentScope+() = func
and vlen.getParentScope+() = func
select func, vdata, vlimit, vsize, vlen
