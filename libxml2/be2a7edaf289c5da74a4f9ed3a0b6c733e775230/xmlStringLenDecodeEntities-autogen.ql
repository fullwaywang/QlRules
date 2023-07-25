/**
 * @name libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-xmlStringLenDecodeEntities
 * @id cpp/libxml2/be2a7edaf289c5da74a4f9ed3a0b6c733e775230/xmlStringLenDecodeEntities
 * @description libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-parser.c-xmlStringLenDecodeEntities CVE-2014-3660
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2703, Variable vent_2712, LogicalAndExpr target_2, LogicalOrExpr target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2703
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vent_2712
		and target_0.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_2703, Variable vent_2712, LogicalAndExpr target_7, EqualityOperation target_8, ExprStmt target_9, ExprStmt target_10, EqualityOperation target_11) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("xmlParserEntityCheck")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2703
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vent_2712
		and target_1.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="38"
		and target_2.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vctxt_2703, LogicalOrExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2703
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2703
}

predicate func_4(Parameter vctxt_2703, Variable vent_2712, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_4.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2703
		and target_4.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_4.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2712
		and target_4.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_5(Parameter vctxt_2703, Variable vent_2712, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vent_2712
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseStringEntityRef")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2703
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const xmlChar *")
}

predicate func_6(Variable vent_2712, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vent_2712
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(LogicalAndExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="37"
		and target_7.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_8(Parameter vctxt_2703, EqualityOperation target_8) {
		target_8.getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_8.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_8.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2703
}

predicate func_9(Parameter vctxt_2703, Variable vent_2712, ExprStmt target_9) {
		target_9.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_9.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2703
		and target_9.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_9.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2712
		and target_9.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_10(Parameter vctxt_2703, Variable vent_2712, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vent_2712
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseStringPEReference")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2703
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const xmlChar *")
}

predicate func_11(Variable vent_2712, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vent_2712
		and target_11.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_2703, Variable vent_2712, LogicalAndExpr target_2, LogicalOrExpr target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6, LogicalAndExpr target_7, EqualityOperation target_8, ExprStmt target_9, ExprStmt target_10, EqualityOperation target_11
where
not func_0(vctxt_2703, vent_2712, target_2, target_3, target_4, target_5, target_6)
and not func_1(vctxt_2703, vent_2712, target_7, target_8, target_9, target_10, target_11)
and func_2(target_2)
and func_3(vctxt_2703, target_3)
and func_4(vctxt_2703, vent_2712, target_4)
and func_5(vctxt_2703, vent_2712, target_5)
and func_6(vent_2712, target_6)
and func_7(target_7)
and func_8(vctxt_2703, target_8)
and func_9(vctxt_2703, vent_2712, target_9)
and func_10(vctxt_2703, vent_2712, target_10)
and func_11(vent_2712, target_11)
and vctxt_2703.getType().hasName("xmlParserCtxtPtr")
and vent_2712.getType().hasName("xmlEntityPtr")
and vctxt_2703.getFunction() = func
and vent_2712.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
