/**
 * @name libxml2-00906759053986b8079985644172085f74331f83-xmlParseConditionalSections
 * @id cpp/libxml2/00906759053986b8079985644172085f74331f83/xmlParseConditionalSections
 * @description libxml2-00906759053986b8079985644172085f74331f83-parser.c-xmlParseConditionalSections CVE-2016-4447
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6811, LogicalAndExpr target_1, ExprStmt target_2, LogicalAndExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlHaltParser")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6811
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_6811, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("const xmlChar *")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="consumed"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811
}

predicate func_2(Parameter vctxt_6811, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6811
		and target_2.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_6811, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="filename"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811
}

from Function func, Parameter vctxt_6811, LogicalAndExpr target_1, ExprStmt target_2, LogicalAndExpr target_3
where
not func_0(vctxt_6811, target_1, target_2, target_3)
and func_1(vctxt_6811, target_1)
and func_2(vctxt_6811, target_2)
and func_3(vctxt_6811, target_3)
and vctxt_6811.getType().hasName("xmlParserCtxtPtr")
and vctxt_6811.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
