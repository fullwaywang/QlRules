/**
 * @name libxml2-8598060bacada41a0eb09d95c97744ff4e428f8e-xmlParserEntityCheck
 * @id cpp/libxml2/8598060bacada41a0eb09d95c97744ff4e428f8e/xmlParserEntityCheck
 * @description libxml2-8598060bacada41a0eb09d95c97744ff4e428f8e-xmlParserEntityCheck CVE-2021-3541
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Parameter vctxt_139, Variable vconsumed_142, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_139
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vconsumed_142
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconsumed_142
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_7(Parameter vctxt_139, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_139
		and target_7.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_7))
}

predicate func_8(Function func) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_8))
}

predicate func_11(Parameter vctxt_139) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="nbentities"
		and target_11.getQualifier().(VariableAccess).getTarget()=vctxt_139)
}

from Function func, Parameter vctxt_139, Variable vconsumed_142
where
not func_0(func)
and not func_1(vctxt_139, vconsumed_142, func)
and not func_7(vctxt_139, func)
and not func_8(func)
and vctxt_139.getType().hasName("xmlParserCtxtPtr")
and func_11(vctxt_139)
and vconsumed_142.getType().hasName("size_t")
and vctxt_139.getParentScope+() = func
and vconsumed_142.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
