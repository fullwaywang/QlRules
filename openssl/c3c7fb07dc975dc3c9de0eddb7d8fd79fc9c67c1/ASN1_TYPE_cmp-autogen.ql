/**
 * @name openssl-c3c7fb07dc975dc3c9de0eddb7d8fd79fc9c67c1-ASN1_TYPE_cmp
 * @id cpp/openssl/c3c7fb07dc975dc3c9de0eddb7d8fd79fc9c67c1/ASN1-TYPE-cmp
 * @description openssl-c3c7fb07dc975dc3c9de0eddb7d8fd79fc9c67c1-ASN1_TYPE_cmp CVE-2015-0286
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SwitchCase target_0 |
		target_0.getExpr().(Literal).getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter va_111, Parameter vb_111, Variable vresult_113) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_113
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="boolean"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_111
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="boolean"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_111
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_111)
}

predicate func_2(Parameter va_111) {
	exists(BreakStmt target_2 |
		target_2.toString() = "break;"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_111)
}

predicate func_3(Parameter va_111) {
	exists(ValueFieldAccess target_3 |
		target_3.getTarget().getName()="object"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_111)
}

predicate func_4(Parameter vb_111) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="object"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_111)
}

from Function func, Parameter va_111, Parameter vb_111, Variable vresult_113
where
not func_0(func)
and not func_1(va_111, vb_111, vresult_113)
and not func_2(va_111)
and va_111.getType().hasName("const ASN1_TYPE *")
and func_3(va_111)
and vb_111.getType().hasName("const ASN1_TYPE *")
and func_4(vb_111)
and vresult_113.getType().hasName("int")
and va_111.getParentScope+() = func
and vb_111.getParentScope+() = func
and vresult_113.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
