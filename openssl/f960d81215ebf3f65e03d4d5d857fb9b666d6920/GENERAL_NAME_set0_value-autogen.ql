import cpp

predicate func_0(Parameter va) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="other"
		and target_0.getType().hasName("ASN1_TYPE *")
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va)
}

predicate func_1(Parameter va, Parameter vvalue) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getType().hasName("EDIPARTYNAME *")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getType().hasName("EDIPARTYNAME *")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue)
}

from Function func, Parameter va, Parameter vvalue
where
func_0(va)
and not func_1(va, vvalue)
and va.getType().hasName("GENERAL_NAME *")
and vvalue.getType().hasName("void *")
and va.getParentScope+() = func
and vvalue.getParentScope+() = func
select func, va, vvalue
