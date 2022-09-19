import cpp

predicate func_0(Function func) {
	exists(MulExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getValue()="32768"
		and target_0.getLeftOperand().(Literal).getValue()="2"
		and target_0.getRightOperand().(Literal).getValue()="16384"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vdata, Function func) {
	exists(MulExpr target_3 |
		target_3.getType().hasName("long")
		and target_3.getLeftOperand() instanceof Literal
		and target_3.getRightOperand().(ValueFieldAccess).getTarget().getName()="buffer_size"
		and target_3.getRightOperand().(ValueFieldAccess).getType().hasName("long")
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("UserDefined")
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_3.getEnclosingFunction() = func)
}

from Function func, Variable vdata
where
not func_0(func)
and not func_1(func)
and func_2(func)
and func_3(vdata, func)
and vdata.getType().hasName("Curl_easy *")
and vdata.getParentScope+() = func
select func, vdata
