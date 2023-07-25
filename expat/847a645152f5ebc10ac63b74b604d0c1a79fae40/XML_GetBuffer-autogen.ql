/**
 * @name expat-847a645152f5ebc10ac63b74b604d0c1a79fae40-XML_GetBuffer
 * @id cpp/expat/847a645152f5ebc10ac63b74b604d0c1a79fae40/XML-GetBuffer
 * @description expat-847a645152f5ebc10ac63b74b604d0c1a79fae40-expat/lib/xmlparse.c-XML_GetBuffer CVE-2022-23852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparser_2037, Variable vkeep_2056, Variable vneededSize_2059, RelationalOperation target_1, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vkeep_2056
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vneededSize_2059
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_errorCode"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation())
		and target_6.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vparser_2037, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_1.getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_1.getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferEnd"
		and target_1.getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_1.getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_1.getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_1.getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="m_bufferEnd"
		and target_1.getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_1.getLesserOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_2(Parameter vparser_2037, Variable vkeep_2056, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkeep_2056
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferPtr"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_buffer"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="m_bufferPtr"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="m_buffer"
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_3(Parameter vparser_2037, Variable vneededSize_2059, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vneededSize_2059
		and target_3.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_3.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_3.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_buffer"
		and target_3.getGreaterOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_3.getGreaterOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_3.getGreaterOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_3.getGreaterOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="m_buffer"
		and target_3.getGreaterOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_3.getGreaterOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_4(Variable vkeep_2056, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkeep_2056
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1024"
}

predicate func_5(Variable vkeep_2056, Variable vneededSize_2059, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vneededSize_2059
		and target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vkeep_2056
}

predicate func_6(Variable vneededSize_2059, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vneededSize_2059
		and target_6.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vparser_2037, Variable vkeep_2056, Variable vneededSize_2059, RelationalOperation target_1, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_0(vparser_2037, vkeep_2056, vneededSize_2059, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(vparser_2037, target_1)
and func_2(vparser_2037, vkeep_2056, target_2)
and func_3(vparser_2037, vneededSize_2059, target_3)
and func_4(vkeep_2056, target_4)
and func_5(vkeep_2056, vneededSize_2059, target_5)
and func_6(vneededSize_2059, target_6)
and vparser_2037.getType().hasName("XML_Parser")
and vkeep_2056.getType().hasName("int")
and vneededSize_2059.getType().hasName("int")
and vparser_2037.getParentScope+() = func
and vkeep_2056.getParentScope+() = func
and vneededSize_2059.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
