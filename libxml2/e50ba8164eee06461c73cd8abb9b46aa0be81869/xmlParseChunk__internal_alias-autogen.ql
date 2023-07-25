/**
 * @name libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-xmlParseChunk__internal_alias
 * @id cpp/libxml2/e50ba8164eee06461c73cd8abb9b46aa0be81869/xmlParseChunk--internal-alias
 * @description libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-parser.c-xmlParseChunk__internal_alias CVE-2013-2877
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_12109, ExprStmt target_1, LogicalAndExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_12109
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getTarget().getName()="errNo"
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_12109
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_12109, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("xmlParseTryOrFinish")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_12109
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Parameter vctxt_12109, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_12109
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="10000000"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_12109
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_12109, ExprStmt target_1, LogicalAndExpr target_2
where
not func_0(vctxt_12109, target_1, target_2, func)
and func_1(vctxt_12109, target_1)
and func_2(vctxt_12109, target_2)
and vctxt_12109.getType().hasName("xmlParserCtxtPtr")
and vctxt_12109.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
