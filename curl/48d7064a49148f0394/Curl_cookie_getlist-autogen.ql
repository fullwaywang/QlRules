import cpp

predicate func_0(Variable vnewco, Variable vmatches) {
	exists(IfStmt target_0 |
		target_0.getCondition().(GEExpr).getType().hasName("int")
		and target_0.getCondition().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vmatches
		and target_0.getCondition().(GEExpr).getLesserOperand().(Literal).getValue()="150"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Included max number of cookies (%u) in request!"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmatches
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnewco)
}

from Function func, Variable vnewco, Variable vmatches
where
not func_0(vnewco, vmatches)
and vnewco.getType().hasName("Cookie *")
and vmatches.getType().hasName("size_t")
and vnewco.getParentScope+() = func
and vmatches.getParentScope+() = func
select func, vnewco, vmatches
