/**
 * @name libexpat-4a32da87e931ba54393d465bb77c40b5c33d343b-internalEntityProcessor
 * @id cpp/libexpat/4a32da87e931ba54393d465bb77c40b5c33d343b/internalEntityProcessor
 * @description libexpat-4a32da87e931ba54393d465bb77c40b5c33d343b-internalEntityProcessor CVE-2022-40674
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ventity_5772, Variable vresult_5775, Parameter vs_5770, Parameter vend_5770, Parameter vnextPtr_5771, Parameter vparser_5770) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_5775
		//and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
        and func_4(target_0.getExpr().(AssignExpr).getRValue(), vs_5770, vend_5770, vnextPtr_5771, vparser_5770)
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_param"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_5772)
}

predicate func_1(Variable ventity_5772, Variable vresult_5775, Parameter vparser_5770) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_5775
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("storeRawNames")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_5770
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="is_param"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_5772)
}

predicate func_4(FunctionCall target_4, Parameter vs_5770, Parameter vend_5770, Parameter vnextPtr_5771, Parameter vparser_5770) {
		target_4.getTarget().hasName("doContent")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vparser_5770
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="m_parentParser"
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_5770
		and target_4.getArgument(1).(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_4.getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_4.getArgument(2).(PointerFieldAccess).getTarget().getName()="m_encoding"
		and target_4.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_5770
		and target_4.getArgument(3).(VariableAccess).getTarget()=vs_5770
		and target_4.getArgument(4).(VariableAccess).getTarget()=vend_5770
		and target_4.getArgument(5).(VariableAccess).getTarget()=vnextPtr_5771
		and target_4.getArgument(6).(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="finalBuffer"
		and target_4.getArgument(6).(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_parsingStatus"
		and target_4.getArgument(6).(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_5770
}

predicate func_5(Parameter vparser_5770) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="m_processor"
		and target_5.getQualifier().(VariableAccess).getTarget()=vparser_5770)
}

from Function func, FunctionCall fc, Parameter vs_5770, Parameter vend_5770, Parameter vnextPtr_5771, Variable ventity_5772, Variable vresult_5775, Parameter vparser_5770
where
not func_0(ventity_5772, vresult_5775, vs_5770, vend_5770, vnextPtr_5771, vparser_5770)
and not func_1(ventity_5772, vresult_5775, vparser_5770)
and func_4(fc, vs_5770, vend_5770, vnextPtr_5771, vparser_5770)
and vs_5770.getType().hasName("const char *")
and vend_5770.getType().hasName("const char *")
and vnextPtr_5771.getType().hasName("const char **")
and ventity_5772.getType().hasName("ENTITY *")
and vresult_5775.getType().hasName("XML_Error")
and vparser_5770.getType().hasName("XML_Parser")
and func_5(vparser_5770)
and vs_5770.getParentScope+() = func
and vend_5770.getParentScope+() = func
and vnextPtr_5771.getParentScope+() = func
and ventity_5772.getParentScope+() = func
and vresult_5775.getParentScope+() = func
and vparser_5770.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
