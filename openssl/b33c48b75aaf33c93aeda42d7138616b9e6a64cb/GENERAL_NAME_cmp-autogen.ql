/**
 * @name openssl-b33c48b75aaf33c93aeda42d7138616b9e6a64cb-GENERAL_NAME_cmp
 * @id cpp/openssl/b33c48b75aaf33c93aeda42d7138616b9e6a64cb/GENERAL-NAME-cmp
 * @description openssl-b33c48b75aaf33c93aeda42d7138616b9e6a64cb-GENERAL_NAME_cmp CVE-2020-1971
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter va_62) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="other"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_62)
}

predicate func_1(Parameter vb_62) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="other"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_62)
}

predicate func_2(Parameter va_62, Parameter vb_62, Variable vresult_64) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_64
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("edipartyname_cmp")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_62
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_62
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_62)
}

predicate func_3(Parameter va_62) {
	exists(BreakStmt target_3 |
		target_3.toString() = "break;"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_62)
}

from Function func, Parameter va_62, Parameter vb_62, Variable vresult_64
where
func_0(va_62)
and func_1(vb_62)
and not func_2(va_62, vb_62, vresult_64)
and not func_3(va_62)
and va_62.getType().hasName("GENERAL_NAME *")
and vb_62.getType().hasName("GENERAL_NAME *")
and vresult_64.getType().hasName("int")
and va_62.getParentScope+() = func
and vb_62.getParentScope+() = func
and vresult_64.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
