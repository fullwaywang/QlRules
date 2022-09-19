import cpp

predicate func_0(Variable vcrl_score, Variable vbest_score) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LTExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vcrl_score
		and target_0.getLeftOperand().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vbest_score
		and target_0.getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vcrl_score
		and target_0.getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vcrl_score, Variable vbest_score, Variable vcrl, Variable vbest_crl, Variable vday, Variable vsec) {
	exists(LogicalAndExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_1.getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vcrl_score
		and target_1.getLeftOperand().(EQExpr).getRightOperand().(VariableAccess).getTarget()=vbest_score
		and target_1.getRightOperand().(NEExpr).getType().hasName("int")
		and target_1.getRightOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vbest_crl
		and target_1.getRightOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(1).(VariableDeclarationEntry).getType().hasName("int")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ASN1_TIME_diff")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vday
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsec
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbest_crl
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrl
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vday
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vsec
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vcrl_score, Variable vbest_score) {
	exists(LTExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vcrl_score
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vbest_score)
}

predicate func_3(Variable vcrl_score, Variable vbest_score, Variable vcrl, Variable vbest_crl, Variable vday, Variable vsec) {
	exists(EQExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(VariableAccess).getTarget()=vcrl_score
		and target_3.getRightOperand().(VariableAccess).getTarget()=vbest_score
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(1).(VariableDeclarationEntry).getType().hasName("int")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ASN1_TIME_diff")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vday
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsec
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbest_crl
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrl
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vday
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getLeftOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vsec
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getRightOperand().(LEExpr).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vcrl_score, Variable vbest_score, Variable vcrl, Variable vbest_crl, Variable vday, Variable vsec
where
not func_0(vcrl_score, vbest_score)
and not func_1(vcrl_score, vbest_score, vcrl, vbest_crl, vday, vsec)
and func_2(vcrl_score, vbest_score)
and func_3(vcrl_score, vbest_score, vcrl, vbest_crl, vday, vsec)
and vcrl_score.getType().hasName("int")
and vbest_score.getType().hasName("int")
and vcrl.getType().hasName("X509_CRL *")
and vbest_crl.getType().hasName("X509_CRL *")
and vday.getType().hasName("int")
and vsec.getType().hasName("int")
and vcrl_score.getParentScope+() = func
and vbest_score.getParentScope+() = func
and vcrl.getParentScope+() = func
and vbest_crl.getParentScope+() = func
and vday.getParentScope+() = func
and vsec.getParentScope+() = func
select func, vcrl_score, vbest_score, vcrl, vbest_crl, vday, vsec
