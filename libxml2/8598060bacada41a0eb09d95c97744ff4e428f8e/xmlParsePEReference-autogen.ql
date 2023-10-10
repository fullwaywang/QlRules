/**
 * @name libxml2-8598060bacada41a0eb09d95c97744ff4e428f8e-xmlParsePEReference
 * @id cpp/libxml2/8598060bacada41a0eb09d95c97744ff4e428f8e/xmlParsePEReference
 * @description libxml2-8598060bacada41a0eb09d95c97744ff4e428f8e-xmlParsePEReference CVE-2021-3541
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ventity_7885, Parameter vctxt_7882) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_7882
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=ventity_7885
		and target_0.getCondition().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_7885
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_7885)
}

predicate func_1(Variable ventity_7885) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="etype"
		and target_1.getQualifier().(VariableAccess).getTarget()=ventity_7885)
}

predicate func_2(Variable vname_7884, Parameter vctxt_7882) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlWarningMsg")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_7882
		and target_2.getArgument(2).(StringLiteral).getValue()="Internal: %%%s; is not a parameter entity\n"
		and target_2.getArgument(3).(VariableAccess).getTarget()=vname_7884
		and target_2.getArgument(4).(Literal).getValue()="0")
}

from Function func, Variable vname_7884, Variable ventity_7885, Parameter vctxt_7882
where
not func_0(ventity_7885, vctxt_7882)
and ventity_7885.getType().hasName("xmlEntityPtr")
and func_1(ventity_7885)
and vctxt_7882.getType().hasName("xmlParserCtxtPtr")
and func_2(vname_7884, vctxt_7882)
and vname_7884.getParentScope+() = func
and ventity_7885.getParentScope+() = func
and vctxt_7882.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
