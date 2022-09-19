import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdata, Variable vnamelen) {
	exists(IfStmt target_1 |
		target_1.getCondition().(GEExpr).getType().hasName("int")
		and target_1.getCondition().(GEExpr).getGreaterOperand().(PrefixIncrExpr).getType().hasName("int")
		and target_1.getCondition().(GEExpr).getLesserOperand().(Literal).getValue()="5"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Reject response due to %u content encodings"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnamelen)
}

from Function func, Parameter vdata, Variable vnamelen
where
not func_0(func)
and not func_1(vdata, vnamelen)
and vdata.getType().hasName("Curl_easy *")
and vnamelen.getType().hasName("size_t")
and vdata.getParentScope+() = func
and vnamelen.getParentScope+() = func
select func, vdata, vnamelen
