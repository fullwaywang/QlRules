/**
 * @name libxml2-afd27c21f6b36e22682b7da20d726bce2dcb2f43-xmlParseXMLDecl
 * @id cpp/libxml2/afd27c21f6b36e22682b7da20d726bce2dcb2f43/xmlParseXMLDecl
 * @description libxml2-afd27c21f6b36e22682b7da20d726bce2dcb2f43-parser.c-xmlParseXMLDecl CVE-2015-7498
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_10604, ExprStmt target_2, EqualityOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_10604
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_10604, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="errNo"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_10604
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_2(Parameter vctxt_10604, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("xmlParseEncodingDecl")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_10604
}

from Function func, Parameter vctxt_10604, EqualityOperation target_1, ExprStmt target_2
where
not func_0(vctxt_10604, target_2, target_1)
and func_1(vctxt_10604, target_1)
and func_2(vctxt_10604, target_2)
and vctxt_10604.getType().hasName("xmlParserCtxtPtr")
and vctxt_10604.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
