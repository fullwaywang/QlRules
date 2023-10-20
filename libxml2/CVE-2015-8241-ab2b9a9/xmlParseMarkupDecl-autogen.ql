/**
 * @name libxml2-ab2b9a93ff19cedde7befbf2fcc48c6e352b6cbe-xmlParseMarkupDecl
 * @id cpp/libxml2/ab2b9a93ff19cedde7befbf2fcc48c6e352b6cbe/xmlParseMarkupDecl
 * @description libxml2-ab2b9a93ff19cedde7befbf2fcc48c6e352b6cbe-parser.c-xmlParseMarkupDecl CVE-2015-8241
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_6947, ExprStmt target_1, LogicalAndExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6947
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_6947, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("xmlParsePI")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_6947
}

predicate func_2(Parameter vctxt_6947, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="external"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6947
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_6947
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vctxt_6947, ExprStmt target_1, LogicalAndExpr target_2
where
not func_0(vctxt_6947, target_1, target_2, func)
and func_1(vctxt_6947, target_1)
and func_2(vctxt_6947, target_2)
and vctxt_6947.getType().hasName("xmlParserCtxtPtr")
and vctxt_6947.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
