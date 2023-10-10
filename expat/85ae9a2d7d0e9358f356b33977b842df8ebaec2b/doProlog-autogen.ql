/**
 * @name expat-85ae9a2d7d0e9358f356b33977b842df8ebaec2b-doProlog
 * @id cpp/expat/85ae9a2d7d0e9358f356b33977b842df8ebaec2b/doProlog
 * @description expat-85ae9a2d7d0e9358f356b33977b842df8ebaec2b-expat/lib/xmlparse.c-doProlog CVE-2021-46143
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparser_4369, Literal target_0) {
		target_0.getValue()="5180"
		and not target_0.getValue()="5195"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("entityTrackingOnOpen")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_4369
}

predicate func_1(Parameter vparser_4369, Literal target_1) {
		target_1.getValue()="5184"
		and not target_1.getValue()="5199"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("entityTrackingOnClose")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_4369
}

predicate func_2(Parameter vparser_4369, Literal target_2) {
		target_2.getValue()="5188"
		and not target_2.getValue()="5203"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("entityTrackingOnClose")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_4369
}

predicate func_3(Parameter vparser_4369, IfStmt target_4, ValueFieldAccess target_5) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="m_groupSize"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_4369
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="2147483647"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vparser_4369, IfStmt target_4) {
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="m_groupSize"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_4369
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_groupConnector"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_4369
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="scaffIndex"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scaffIndex"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_groupConnector"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_4369
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="malloc_fcn"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_groupSize"
		and target_4.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(AssignExpr).getRValue().(Literal).getValue()="32"
}

predicate func_5(Parameter vparser_4369, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="realloc_fcn"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_4369
}

from Function func, Parameter vparser_4369, Literal target_0, Literal target_1, Literal target_2, IfStmt target_4, ValueFieldAccess target_5
where
func_0(vparser_4369, target_0)
and func_1(vparser_4369, target_1)
and func_2(vparser_4369, target_2)
and not func_3(vparser_4369, target_4, target_5)
and func_4(vparser_4369, target_4)
and func_5(vparser_4369, target_5)
and vparser_4369.getType().hasName("XML_Parser")
and vparser_4369.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
