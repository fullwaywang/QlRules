import cpp

predicate func_0(Parameter vs, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dtls1_record_bitmap_update")
		and target_0.getExpr().(FunctionCall).getType().hasName("void")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vs
where
not func_0(vs, func)
and vs.getType().hasName("SSL *")
and vs.getParentScope+() = func
select func, vs
