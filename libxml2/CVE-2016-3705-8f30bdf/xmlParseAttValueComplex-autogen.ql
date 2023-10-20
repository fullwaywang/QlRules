/**
 * @name libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-xmlParseAttValueComplex
 * @id cpp/libxml2/8f30bdff69edac9075f4663ce3b56b0c52d48ce6/xmlParseAttValueComplex
 * @description libxml2-8f30bdff69edac9075f4663ce3b56b0c52d48ce6-parser.c-xmlParseAttValueComplex CVE-2016-3705
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_3993, EqualityOperation target_4, LogicalAndExpr target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_3993, EqualityOperation target_4, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vctxt_3993, LogicalAndExpr target_7, ExprStmt target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_2.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_2.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vctxt_3993, LogicalAndExpr target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_3.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
}

predicate func_5(Parameter vctxt_3993, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="replaceEntities"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Parameter vctxt_3993, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStringDecodeEntities")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3993
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_7(LogicalAndExpr target_7) {
		target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="etype"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Parameter vctxt_3993, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStringDecodeEntities")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3993
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_9(Parameter vctxt_3993, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="checked"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlEntityPtr")
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3993
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("unsigned long")
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vctxt_3993, EqualityOperation target_4, LogicalAndExpr target_5, ExprStmt target_6, LogicalAndExpr target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vctxt_3993, target_4, target_5, target_6)
and not func_1(vctxt_3993, target_4, target_6)
and not func_2(vctxt_3993, target_7, target_8)
and not func_3(vctxt_3993, target_7, target_8, target_9)
and func_4(target_4)
and func_5(vctxt_3993, target_5)
and func_6(vctxt_3993, target_6)
and func_7(target_7)
and func_8(vctxt_3993, target_8)
and func_9(vctxt_3993, target_9)
and vctxt_3993.getType().hasName("xmlParserCtxtPtr")
and vctxt_3993.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
