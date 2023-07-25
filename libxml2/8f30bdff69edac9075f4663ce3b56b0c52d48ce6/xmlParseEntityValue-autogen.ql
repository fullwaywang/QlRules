/**
 * @name libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-xmlParseEntityValue
 * @id cpp/libxml2/8f30bdff69edac9075f4663ce3b56b0c52d48ce6/xmlParseEntityValue
 * @description libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-parser.c-xmlParseEntityValue CVE-2016-3705
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_3846, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3846
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_3846, EqualityOperation target_2, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3846
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlChar")
}

predicate func_3(Parameter vctxt_3846, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3846
}

predicate func_4(Parameter vctxt_3846, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStringDecodeEntities")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3846
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

from Function func, Parameter vctxt_3846, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vctxt_3846, target_2, target_3, target_4)
and not func_1(vctxt_3846, target_2, target_4)
and func_2(target_2)
and func_3(vctxt_3846, target_3)
and func_4(vctxt_3846, target_4)
and vctxt_3846.getType().hasName("xmlParserCtxtPtr")
and vctxt_3846.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
