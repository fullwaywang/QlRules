import cpp

predicate func_0(Parameter vs, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getType().hasName("size_t")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="peer_sigalgslen"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("size_t")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("struct <unnamed>")
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vs
where
not func_0(vs, func)
and vs.getType().hasName("SSL *")
and vs.getParentScope+() = func
select func, vs
