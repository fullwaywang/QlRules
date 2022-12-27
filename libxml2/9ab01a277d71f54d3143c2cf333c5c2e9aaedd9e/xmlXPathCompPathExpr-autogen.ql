/**
 * @name libxml2-9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e-xmlXPathCompPathExpr
 * @id cpp/libxml2/9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e/xmlXPathCompPathExpr
 * @description libxml2-9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e-xmlXPathCompPathExpr CVE-2016-5131
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_10627, Variable vlc_10628, Variable vname_10629) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="xptr"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_10627
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrEqual")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_10629
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="range-to"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_10628
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getElse() instanceof BlockStmt
		and target_0.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xmlXPathIsNodeType")
		and target_0.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_10629)
}

predicate func_2(Variable vlc_10628, Variable vname_10629) {
	exists(BlockStmt target_2 |
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlc_10628
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xmlXPathIsNodeType")
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_10629)
}

predicate func_3(Parameter vctxt_10627) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="cur"
		and target_3.getQualifier().(VariableAccess).getTarget()=vctxt_10627)
}

predicate func_4(Variable vname_10629) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("xmlXPathIsNodeType")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vname_10629)
}

from Function func, Parameter vctxt_10627, Variable vlc_10628, Variable vname_10629
where
not func_0(vctxt_10627, vlc_10628, vname_10629)
and func_2(vlc_10628, vname_10629)
and vctxt_10627.getType().hasName("xmlXPathParserContextPtr")
and func_3(vctxt_10627)
and vlc_10628.getType().hasName("int")
and vname_10629.getType().hasName("xmlChar *")
and func_4(vname_10629)
and vctxt_10627.getParentScope+() = func
and vlc_10628.getParentScope+() = func
and vname_10629.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
