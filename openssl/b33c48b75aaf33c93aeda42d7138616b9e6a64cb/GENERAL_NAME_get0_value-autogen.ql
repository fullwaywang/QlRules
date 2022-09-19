import cpp

predicate func_0(Parameter va) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="other"
		and target_0.getType().hasName("ASN1_TYPE *")
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va)
}

predicate func_1(Parameter va) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_1.getExpr().(ValueFieldAccess).getType().hasName("EDIPARTYNAME *")
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va)
}

from Function func, Parameter va
where
func_0(va)
and not func_1(va)
and va.getType().hasName("const GENERAL_NAME *")
and va.getParentScope+() = func
select func, va
