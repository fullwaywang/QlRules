/**
 * @name libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-xmlParseReference
 * @id cpp/libxml2/23f05e0c33987d6605387b300c4be5da2120a7ab/xmlParseReference
 * @description libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-parser.c-xmlParseReference CVE-2013-0338
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_1.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_1.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7068
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_2(Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_2.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_7067
		and target_2.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vent_7068
		and target_2.getCondition().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_2.getCondition().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_8, ExprStmt target_9) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_3.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_3.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7068
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_8, ExprStmt target_10, ExprStmt target_11) {
	exists(IfStmt target_4 |
		target_4.getCondition().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_4.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_7067
		and target_4.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vent_7068
		and target_4.getCondition().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_4.getCondition().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7068
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parseMode"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
}

predicate func_6(Variable vent_7068, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7068
}

predicate func_7(Parameter vctxt_7067, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDocCopyNode")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_8(Parameter vctxt_7067, LogicalOrExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vent_7068, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("xmlAddEntityReference")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vent_7068
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
}

predicate func_10(Variable vent_7068, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7068
}

predicate func_11(Parameter vctxt_7067, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDocCopyNode")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="myDoc"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7067
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

from Function func, Variable vent_7068, Parameter vctxt_7067, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7, LogicalOrExpr target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11
where
not func_1(vent_7068, vctxt_7067, target_5)
and not func_2(vent_7068, vctxt_7067, target_5, target_6, target_7)
and not func_3(vent_7068, vctxt_7067, target_8, target_9)
and not func_4(vent_7068, vctxt_7067, target_8, target_10, target_11)
and func_5(vent_7068, vctxt_7067, target_5)
and func_6(vent_7068, target_6)
and func_7(vctxt_7067, target_7)
and func_8(vctxt_7067, target_8)
and func_9(vent_7068, target_9)
and func_10(vent_7068, target_10)
and func_11(vctxt_7067, target_11)
and vent_7068.getType().hasName("xmlEntityPtr")
and vctxt_7067.getType().hasName("xmlParserCtxtPtr")
and vent_7068.(LocalVariable).getFunction() = func
and vctxt_7067.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
