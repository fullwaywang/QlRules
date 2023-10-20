/**
 * @name libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-xmlParseEntityDecl
 * @id cpp/libxml2/e50ba8164eee06461c73cd8abb9b46aa0be81869/xmlParseEntityDecl
 * @description libxml2-e50ba8164eee06461c73cd8abb9b46aa0be81869-parser.c-xmlParseEntityDecl CVE-2013-2877
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_5395, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5395
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(14)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_5395, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="78"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="84"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="73"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5395
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="6"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="84"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_5395
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="7"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="89"
}

predicate func_2(Parameter vctxt_5395, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("xmlSAX2EntityDecl")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5395
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const xmlChar *")
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_2.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_5395, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xmlSkipBlankChars")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_5395
}

from Function func, Parameter vctxt_5395, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vctxt_5395, target_1, target_2, target_3)
and func_1(vctxt_5395, target_1)
and func_2(vctxt_5395, target_2)
and func_3(vctxt_5395, target_3)
and vctxt_5395.getType().hasName("xmlParserCtxtPtr")
and vctxt_5395.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
