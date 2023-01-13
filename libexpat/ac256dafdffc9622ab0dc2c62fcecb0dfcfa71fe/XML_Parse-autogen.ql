/**
 * @name libexpat-ac256dafdffc9622ab0dc2c62fcecb0dfcfa71fe-XML_Parse
 * @id cpp/libexpat/ac256dafdffc9622ab0dc2c62fcecb0dfcfa71fe/XML-Parse
 * @description libexpat-ac256dafdffc9622ab0dc2c62fcecb0dfcfa71fe-XML_Parse 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparser_1748, Parameter vs_1748, Parameter vlen_1748) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparser_1748
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparser_1748
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_1748
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vs_1748
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_1748
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vparser_1748, Parameter vs_1748, Parameter vlen_1748) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_errorCode"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_1748
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparser_1748
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_1748
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vs_1748
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_1748
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vparser_1748) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vparser_1748
		and target_2.getAnOperand().(Literal).getValue()="0")
}

from Function func, Parameter vparser_1748, Parameter vs_1748, Parameter vlen_1748
where
not func_0(vparser_1748, vs_1748, vlen_1748)
and func_1(vparser_1748, vs_1748, vlen_1748)
and vparser_1748.getType().hasName("XML_Parser")
and func_2(vparser_1748)
and vs_1748.getType().hasName("const char *")
and vlen_1748.getType().hasName("int")
and vparser_1748.getParentScope+() = func
and vs_1748.getParentScope+() = func
and vlen_1748.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
