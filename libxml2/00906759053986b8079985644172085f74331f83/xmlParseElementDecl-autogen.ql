/**
 * @name libxml2-00906759053986b8079985644172085f74331f83-xmlParseElementDecl
 * @id cpp/libxml2/00906759053986b8079985644172085f74331f83/xmlParseElementDecl
 * @description libxml2-00906759053986b8079985644172085f74331f83-xmlParseElementDecl CVE-2016-4447
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6698) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6698
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6698
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6698
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6698
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13")
}

from Function func, Parameter vctxt_6698
where
not func_0(vctxt_6698)
and vctxt_6698.getType().hasName("xmlParserCtxtPtr")
and vctxt_6698.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
