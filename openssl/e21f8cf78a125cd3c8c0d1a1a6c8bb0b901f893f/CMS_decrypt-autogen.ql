/**
 * @name openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-CMS_decrypt
 * @id cpp/openssl/e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f/CMS-decrypt
 * @description openssl-e21f8cf78a125cd3c8c0d1a1a6c8bb0b901f893f-crypto/cms/cms_smime.c-CMS_decrypt CVE-2019-1563
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcert_725, LogicalAndExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vcert_725
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="havenocert"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="havenocert"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="encryptedContentInfo"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="envelopedData"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcert_725, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vcert_725
}

from Function func, Parameter vcert_725, LogicalAndExpr target_1
where
not func_0(vcert_725, target_1, func)
and func_1(vcert_725, target_1)
and vcert_725.getType().hasName("X509 *")
and vcert_725.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
