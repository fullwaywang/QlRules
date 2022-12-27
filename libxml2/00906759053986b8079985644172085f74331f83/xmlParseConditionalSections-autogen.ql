/**
 * @name libxml2-00906759053986b8079985644172085f74331f83-xmlParseConditionalSections
 * @id cpp/libxml2/00906759053986b8079985644172085f74331f83/xmlParseConditionalSections
 * @description libxml2-00906759053986b8079985644172085f74331f83-xmlParseConditionalSections CVE-2016-4447
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6811, Variable vcheck_6842, Variable vcons_6843) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlHaltParser")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6811
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcheck_6842
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcons_6843
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="consumed"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6811)
}

predicate func_1(Parameter vctxt_6811) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xmlFatalErr")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctxt_6811
		and target_1.getArgument(2).(Literal).getValue()="0")
}

from Function func, Parameter vctxt_6811, Variable vcheck_6842, Variable vcons_6843
where
not func_0(vctxt_6811, vcheck_6842, vcons_6843)
and vctxt_6811.getType().hasName("xmlParserCtxtPtr")
and func_1(vctxt_6811)
and vcheck_6842.getType().hasName("const xmlChar *")
and vcons_6843.getType().hasName("unsigned int")
and vctxt_6811.getParentScope+() = func
and vcheck_6842.getParentScope+() = func
and vcons_6843.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
