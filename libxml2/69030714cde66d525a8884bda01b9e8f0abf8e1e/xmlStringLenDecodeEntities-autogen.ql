/**
 * @name libxml2-69030714cde66d525a8884bda01b9e8f0abf8e1e-xmlStringLenDecodeEntities
 * @id cpp/libxml2/69030714cde66d525a8884bda01b9e8f0abf8e1e/xmlStringLenDecodeEntities
 * @description libxml2-69030714cde66d525a8884bda01b9e8f0abf8e1e-xmlStringLenDecodeEntities CVE-2015-5312
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2730, Variable vent_2739) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2730
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2730
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vent_2739
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2739
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vctxt_2730) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="depth"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctxt_2730)
}

from Function func, Parameter vctxt_2730, Variable vent_2739
where
not func_0(vctxt_2730, vent_2739)
and vctxt_2730.getType().hasName("xmlParserCtxtPtr")
and func_1(vctxt_2730)
and vent_2739.getType().hasName("xmlEntityPtr")
and vctxt_2730.getParentScope+() = func
and vent_2739.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
