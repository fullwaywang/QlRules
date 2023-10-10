/**
 * @name openssl-6e629b5be45face20b4ca71c4fcbfed78b864a2e-get_crl_sk
 * @id cpp/openssl/6e629b5be45face20b4ca71c4fcbfed78b864a2e/get-crl-sk
 * @description openssl-6e629b5be45face20b4ca71c4fcbfed78b864a2e-crypto/x509/x509_vfy.c-get_crl_sk CVE-2016-7052
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcrl_score_1117, ContinueStmt target_4, ExprStmt target_5, RelationalOperation target_2) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcrl_score_1117
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbest_crl_1120, BlockStmt target_6, PointerFieldAccess target_7) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbest_crl_1120
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcrl_score_1117, Variable vbest_score_1117, ContinueStmt target_4, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vcrl_score_1117
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vbest_score_1117
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vcrl_score_1117, Variable vbest_score_1117, BlockStmt target_6, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vcrl_score_1117
		and target_3.getAnOperand().(VariableAccess).getTarget()=vbest_score_1117
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(ContinueStmt target_4) {
		target_4.toString() = "continue;"
}

predicate func_5(Variable vcrl_score_1117, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcrl_score_1117
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_crl_score")
}

predicate func_6(Variable vbest_crl_1120, BlockStmt target_6) {
		target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ASN1_TIME_diff")
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbest_crl_1120
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="lastUpdate"
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_6.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getStmt(1).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
}

predicate func_7(Variable vbest_crl_1120, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="lastUpdate"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="crl"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbest_crl_1120
}

from Function func, Variable vcrl_score_1117, Variable vbest_score_1117, Variable vbest_crl_1120, RelationalOperation target_2, EqualityOperation target_3, ContinueStmt target_4, ExprStmt target_5, BlockStmt target_6, PointerFieldAccess target_7
where
not func_0(vcrl_score_1117, target_4, target_5, target_2)
and not func_1(vbest_crl_1120, target_6, target_7)
and func_2(vcrl_score_1117, vbest_score_1117, target_4, target_2)
and func_3(vcrl_score_1117, vbest_score_1117, target_6, target_3)
and func_4(target_4)
and func_5(vcrl_score_1117, target_5)
and func_6(vbest_crl_1120, target_6)
and func_7(vbest_crl_1120, target_7)
and vcrl_score_1117.getType().hasName("int")
and vbest_score_1117.getType().hasName("int")
and vbest_crl_1120.getType().hasName("X509_CRL *")
and vcrl_score_1117.getParentScope+() = func
and vbest_score_1117.getParentScope+() = func
and vbest_crl_1120.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
