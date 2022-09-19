import cpp

predicate func_0(Parameter va) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="other"
		and target_0.getType().hasName("ASN1_TYPE *")
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va)
}

predicate func_1(Parameter vb) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="other"
		and target_1.getType().hasName("ASN1_TYPE *")
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_1.getQualifier().(PointerFieldAccess).getType().hasName("union <unnamed>")
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb)
}

predicate func_2(Parameter va, Parameter vb, Variable vresult) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("edipartyname_cmp")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getType().hasName("EDIPARTYNAME *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getType().hasName("EDIPARTYNAME *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb)
}

from Function func, Parameter va, Parameter vb, Variable vresult
where
func_0(va)
and func_1(vb)
and not func_2(va, vb, vresult)
and va.getType().hasName("GENERAL_NAME *")
and vb.getType().hasName("GENERAL_NAME *")
and vresult.getType().hasName("int")
and va.getParentScope+() = func
and vb.getParentScope+() = func
and vresult.getParentScope+() = func
select func, va, vb, vresult
