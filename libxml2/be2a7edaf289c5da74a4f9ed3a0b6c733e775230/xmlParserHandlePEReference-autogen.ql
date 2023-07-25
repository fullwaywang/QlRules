/**
 * @name libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-xmlParserHandlePEReference
 * @id cpp/libxml2/be2a7edaf289c5da74a4f9ed3a0b6c733e775230/xmlParserHandlePEReference
 * @description libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-parser.c-xmlParserHandlePEReference CVE-2014-3660
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2485, EqualityOperation target_1, ExprStmt target_2, EqualityOperation target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2485
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vctxt_2485, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="valid"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2485
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_2485, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="free"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2485
}

from Function func, Parameter vctxt_2485, EqualityOperation target_1, ExprStmt target_2, EqualityOperation target_3
where
not func_0(vctxt_2485, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vctxt_2485, target_2)
and func_3(vctxt_2485, target_3)
and vctxt_2485.getType().hasName("xmlParserCtxtPtr")
and vctxt_2485.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
