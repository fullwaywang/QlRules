/**
 * @name openssl-f960d81215ebf3f65e03d4d5d857fb9b666d6920-GENERAL_NAME_get0_value
 * @id cpp/openssl/f960d81215ebf3f65e03d4d5d857fb9b666d6920/GENERAL-NAME-get0-value
 * @description openssl-f960d81215ebf3f65e03d4d5d857fb9b666d6920-GENERAL_NAME_get0_value CVE-2020-1971
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter va_147) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="other"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_147)
}

predicate func_1(Parameter va_147) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(ValueFieldAccess).getTarget().getName()="ediPartyName"
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_147
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_147)
}

from Function func, Parameter va_147
where
func_0(va_147)
and not func_1(va_147)
and va_147.getType().hasName("const GENERAL_NAME *")
and va_147.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
