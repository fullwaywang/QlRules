/**
 * @name libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-defineAttribute
 * @id cpp/libexpat/9f93e8036e842329863bf20395b8fb8f73834d9e/defineAttribute
 * @description libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-defineAttribute CVE-2022-22824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtype_6120) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1073741823"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vtype_6120) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="allocDefaultAtts"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtype_6120)
}

from Function func, Parameter vtype_6120
where
not func_0(vtype_6120)
and vtype_6120.getType().hasName("ELEMENT_TYPE *")
and func_2(vtype_6120)
and vtype_6120.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
