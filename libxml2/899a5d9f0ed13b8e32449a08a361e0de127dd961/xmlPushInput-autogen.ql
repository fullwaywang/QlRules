/**
 * @name libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-xmlPushInput
 * @id cpp/libxml2/899a5d9f0ed13b8e32449a08a361e0de127dd961/xmlPushInput
 * @description libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-xmlPushInput CVE-2017-16932
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2241, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2241
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="40"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2241
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2241
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1024"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2241
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2241
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFreeInputStream")
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("inputPop")
		and target_0.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2241
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vctxt_2241) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="inputNr"
		and target_4.getQualifier().(VariableAccess).getTarget()=vctxt_2241)
}

from Function func, Parameter vctxt_2241
where
not func_0(vctxt_2241, func)
and vctxt_2241.getType().hasName("xmlParserCtxtPtr")
and func_4(vctxt_2241)
and vctxt_2241.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
