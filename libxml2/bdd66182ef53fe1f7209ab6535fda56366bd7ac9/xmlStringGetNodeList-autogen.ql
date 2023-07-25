/**
 * @name libxml2-bdd66182ef53fe1f7209ab6535fda56366bd7ac9-xmlStringGetNodeList
 * @id cpp/libxml2/bdd66182ef53fe1f7209ab6535fda56366bd7ac9/xmlStringGetNodeList
 * @description libxml2-bdd66182ef53fe1f7209ab6535fda56366bd7ac9-tree.c-xmlStringGetNodeList CVE-2016-3627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vent_1483, LogicalAndExpr target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_1483
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vent_1483, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vent_1483
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_1483
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vent_1483, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_1483
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStringGetNodeList")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const xmlDoc *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
}

from Function func, Variable vent_1483, LogicalAndExpr target_1, ExprStmt target_2
where
not func_0(vent_1483, target_1, target_2)
and func_1(vent_1483, target_1)
and func_2(vent_1483, target_2)
and vent_1483.getType().hasName("xmlEntityPtr")
and vent_1483.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
