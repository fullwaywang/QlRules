/**
 * @name libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-xmlParserEntityCheck
 * @id cpp/libxml2/8f30bdff69edac9075f4663ce3b56b0c52d48ce6/xmlParserEntityCheck
 * @description libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-parser.c-xmlParserEntityCheck CVE-2016-3705
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_126, LogicalAndExpr target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_126
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_126, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_126
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vctxt_126, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStringDecodeEntities")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_126
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_4(Parameter vctxt_126, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="checked"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_126
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("unsigned long")
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vctxt_126, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vctxt_126, target_2, target_3)
and not func_1(vctxt_126, target_2, target_3, target_4)
and func_2(target_2)
and func_3(vctxt_126, target_3)
and func_4(vctxt_126, target_4)
and vctxt_126.getType().hasName("xmlParserCtxtPtr")
and vctxt_126.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
