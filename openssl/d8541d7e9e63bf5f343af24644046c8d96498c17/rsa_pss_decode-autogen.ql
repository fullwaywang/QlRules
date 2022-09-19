import cpp

predicate func_0(Parameter vpmaskHash, Variable vp, Variable vplen, Variable vpss, Variable vparam) {
	exists(LogicalAndExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="algorithm"
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("ASN1_OBJECT *")
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="maskGenAlgorithm"
		and target_0.getLeftOperand().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpss
		and target_0.getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="911"
		and target_0.getRightOperand().(VariableAccess).getTarget()=vparam
		and target_0.getParent().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getParent().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_0.getParent().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam
		and target_0.getParent().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="16"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sequence"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vplen
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sequence"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpmaskHash
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("d2i_X509_ALGOR")
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplen)
}

from Function func, Parameter vpmaskHash, Variable vp, Variable vplen, Variable vpss, Variable vparam
where
not func_0(vpmaskHash, vp, vplen, vpss, vparam)
and vpmaskHash.getType().hasName("X509_ALGOR **")
and vp.getType().hasName("const unsigned char *")
and vplen.getType().hasName("int")
and vpss.getType().hasName("RSA_PSS_PARAMS *")
and vparam.getType().hasName("ASN1_TYPE *")
and vpmaskHash.getParentScope+() = func
and vp.getParentScope+() = func
and vplen.getParentScope+() = func
and vpss.getParentScope+() = func
and vparam.getParentScope+() = func
select func, vpmaskHash, vp, vplen, vpss, vparam
