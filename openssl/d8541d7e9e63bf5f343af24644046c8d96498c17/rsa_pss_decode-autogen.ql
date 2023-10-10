/**
 * @name openssl-d8541d7e9e63bf5f343af24644046c8d96498c17-rsa_pss_decode
 * @id cpp/openssl/d8541d7e9e63bf5f343af24644046c8d96498c17/rsa-pss-decode
 * @description openssl-d8541d7e9e63bf5f343af24644046c8d96498c17-crypto/rsa/rsa_ameth.c-rsa_pss_decode CVE-2015-3194
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vparam_280, BlockStmt target_2, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(VariableAccess).getTarget()=vparam_280
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_280
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpss_266, Variable vparam_280, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("OBJ_obj2nid")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="algorithm"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="maskGenAlgorithm"
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpss_266
		and target_1.getAnOperand().(Literal).getValue()="911"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_280
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vparam_280, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sequence"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_280
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sequence"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_280
}

predicate func_3(Variable vparam_280, LogicalAndExpr target_3) {
		target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_280
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16"
}

from Function func, Variable vpss_266, Variable vparam_280, EqualityOperation target_1, BlockStmt target_2, LogicalAndExpr target_3
where
not func_0(vparam_280, target_2, target_3)
and func_1(vpss_266, vparam_280, target_2, target_1)
and func_2(vparam_280, target_2)
and func_3(vparam_280, target_3)
and vpss_266.getType().hasName("RSA_PSS_PARAMS *")
and vparam_280.getType().hasName("ASN1_TYPE *")
and vpss_266.getParentScope+() = func
and vparam_280.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
