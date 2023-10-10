/**
 * @name expat-9f93e8036e842329863bf20395b8fb8f73834d9e-defineAttribute
 * @id cpp/expat/9f93e8036e842329863bf20395b8fb8f73834d9e/defineAttribute
 * @description expat-9f93e8036e842329863bf20395b8fb8f73834d9e-expat/lib/xmlparse.c-defineAttribute CVE-2022-22822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtype_6120, EqualityOperation target_1, ExprStmt target_2, MulExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1073741823"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtype_6120, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vtype_6120, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vtype_6120, MulExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="allocDefaultAtts"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_6120
		and target_3.getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vtype_6120, EqualityOperation target_1, ExprStmt target_2, MulExpr target_3
where
not func_0(vtype_6120, target_1, target_2, target_3)
and func_1(vtype_6120, target_1)
and func_2(vtype_6120, target_2)
and func_3(vtype_6120, target_3)
and vtype_6120.getType().hasName("ELEMENT_TYPE *")
and vtype_6120.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
