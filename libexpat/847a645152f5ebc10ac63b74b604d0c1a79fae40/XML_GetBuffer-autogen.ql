/**
 * @name libexpat-847a645152f5ebc10ac63b74b604d0c1a79fae40-XML_GetBuffer
 * @id cpp/libexpat/847a645152f5ebc10ac63b74b604d0c1a79fae40/XML-GetBuffer
 * @description libexpat-847a645152f5ebc10ac63b74b604d0c1a79fae40-XML_GetBuffer CVE-2022-23852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_2037, Variable vkeep_2056, Variable vneededSize_2059, Parameter vparser_2037) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vkeep_2056
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vneededSize_2059
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_errorCode"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_2037
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_bufferEnd"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="m_bufferLim"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="m_bufferEnd"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(Literal).getValue()="0")
}

predicate func_3(Variable vkeep_2056) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vkeep_2056
		and target_3.getRValue().(Literal).getValue()="1024")
}

predicate func_4(Variable vneededSize_2059, Parameter vparser_2037) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vneededSize_2059
		and target_4.getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_errorCode"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2037
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Parameter vparser_2037) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="m_buffer"
		and target_5.getQualifier().(VariableAccess).getTarget()=vparser_2037)
}

from Function func, Parameter vlen_2037, Variable vkeep_2056, Variable vneededSize_2059, Parameter vparser_2037
where
not func_0(vlen_2037, vkeep_2056, vneededSize_2059, vparser_2037)
and vlen_2037.getType().hasName("int")
and vkeep_2056.getType().hasName("int")
and func_3(vkeep_2056)
and vneededSize_2059.getType().hasName("int")
and func_4(vneededSize_2059, vparser_2037)
and vparser_2037.getType().hasName("XML_Parser")
and func_5(vparser_2037)
and vlen_2037.getParentScope+() = func
and vkeep_2056.getParentScope+() = func
and vneededSize_2059.getParentScope+() = func
and vparser_2037.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
