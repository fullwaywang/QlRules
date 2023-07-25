/**
 * @name libxslt-2232473733b7313d67de8836ea3b29eec6e8e285-xsltCopyText
 * @id cpp/libxslt/2232473733b7313d67de8836ea3b29eec6e8e285/xsltCopyText
 * @description libxslt-2232473733b7313d67de8836ea3b29eec6e8e285-libxslt/transform.c-xsltCopyText CVE-2019-18197
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_981, LogicalAndExpr target_1, FunctionCall target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lasttext"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_981
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_981, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="doc"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dict"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="doc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dict"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_981
}

predicate func_2(Parameter vctxt_981, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlDictOwns")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_981
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
}

predicate func_3(Parameter vctxt_981, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lasttext"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_981
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="content"
}

from Function func, Parameter vctxt_981, LogicalAndExpr target_1, FunctionCall target_2, ExprStmt target_3
where
not func_0(vctxt_981, target_1, target_2, target_3)
and func_1(vctxt_981, target_1)
and func_2(vctxt_981, target_2)
and func_3(vctxt_981, target_3)
and vctxt_981.getType().hasName("xsltTransformContextPtr")
and vctxt_981.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
