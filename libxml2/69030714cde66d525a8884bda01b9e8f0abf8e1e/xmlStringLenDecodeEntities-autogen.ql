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
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vent_2739
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2739
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vctxt_2730) {
	exists(PostfixDecrExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2730)
}

predicate func_2(Parameter vctxt_2730, Variable vnbchars_2734, Variable vent_2739) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlParserEntityCheck")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_2730
		and target_2.getArgument(1).(VariableAccess).getTarget()=vnbchars_2734
		and target_2.getArgument(2).(VariableAccess).getTarget()=vent_2739
		and target_2.getArgument(3).(Literal).getValue()="0")
}

from Function func, Parameter vctxt_2730, Variable vnbchars_2734, Variable vent_2739
where
not func_0(vctxt_2730, vent_2739)
and vctxt_2730.getType().hasName("xmlParserCtxtPtr")
and func_1(vctxt_2730)
and func_2(vctxt_2730, vnbchars_2734, vent_2739)
and vnbchars_2734.getType().hasName("size_t")
and vent_2739.getType().hasName("xmlEntityPtr")
and vctxt_2730.getParentScope+() = func
and vnbchars_2734.getParentScope+() = func
and vent_2739.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
