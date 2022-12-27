/**
 * @name libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-xmlParsePEReference
 * @id cpp/libxml2/899a5d9f0ed13b8e32449a08a361e0de127dd961/xmlParsePEReference
 * @description libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-xmlParsePEReference CVE-2017-16932
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinput_7829, Parameter vctxt_7825) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlFreeInputStream")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_7829
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("xmlPushInput")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_7825
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinput_7829
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Function func) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_3(Variable vinput_7829, Parameter vctxt_7825) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("xmlPushInput")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctxt_7825
		and target_3.getArgument(1).(VariableAccess).getTarget()=vinput_7829)
}

from Function func, Variable vinput_7829, Parameter vctxt_7825
where
not func_0(vinput_7829, vctxt_7825)
and func_1(func)
and vinput_7829.getType().hasName("xmlParserInputPtr")
and func_3(vinput_7829, vctxt_7825)
and vctxt_7825.getType().hasName("xmlParserCtxtPtr")
and vinput_7829.getParentScope+() = func
and vctxt_7825.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
