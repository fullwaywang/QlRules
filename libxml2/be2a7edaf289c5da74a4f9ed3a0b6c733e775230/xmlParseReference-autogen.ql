/**
 * @name libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-xmlParseReference
 * @id cpp/libxml2/be2a7edaf289c5da74a4f9ed3a0b6c733e775230/xmlParseReference
 * @description libxml2-be2a7edaf289c5da74a4f9ed3a0b6c733e775230-parser.c-xmlParseReference CVE-2014-3660
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vent_7121, Parameter vctxt_7120, LogicalOrExpr target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlParserEntityCheck")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_7120
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getArgument(2).(VariableAccess).getTarget()=vent_7121
		and target_0.getArgument(3).(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vent_7121, Parameter vctxt_7120, FunctionCall target_8) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_1.getAnOperand().(Literal).getValue()="5"
		and target_1.getParent().(AssignAddExpr).getRValue() = target_1
		and target_1.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_1.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vent_7121, Parameter vctxt_7120, LogicalOrExpr target_9, ExprStmt target_10, FunctionCall target_11) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_2.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="5"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getArgument(2).(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vent_7121, Parameter vctxt_7120, ExprStmt target_10, FunctionCall target_11) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_3.getAnOperand().(Literal).getValue()="5"
		and target_3.getParent().(AssignAddExpr).getRValue() = target_3
		and target_3.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_3.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getArgument(2).(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vent_7121, Parameter vctxt_7120, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="length"
		and target_4.getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_4.getParent().(AssignAddExpr).getRValue() = target_4
		and target_4.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_4.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
}

predicate func_5(Variable vent_7121, Parameter vctxt_7120, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="length"
		and target_5.getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_5.getParent().(AssignAddExpr).getRValue() = target_5
		and target_5.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_5.getParent().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
}

predicate func_6(Variable vent_7121, Parameter vctxt_7120, LogicalOrExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7121
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parseMode"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
}

predicate func_7(Variable vent_7121, Parameter vctxt_7120, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_7.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
		and target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_7121
}

predicate func_8(Variable vent_7121, Parameter vctxt_7120, FunctionCall target_8) {
		target_8.getTarget().hasName("xmlParserEntityCheck")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vctxt_7120
		and target_8.getArgument(1).(Literal).getValue()="0"
		and target_8.getArgument(2).(VariableAccess).getTarget()=vent_7121
		and target_8.getArgument(3).(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_8.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
}

predicate func_9(Parameter vctxt_7120, LogicalOrExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="inputNr"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vent_7121, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("xmlAddEntityReference")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vent_7121
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("xmlNodePtr")
}

predicate func_11(Variable vent_7121, Parameter vctxt_7120, FunctionCall target_11) {
		target_11.getTarget().hasName("xmlParserEntityCheck")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vctxt_7120
		and target_11.getArgument(1).(Literal).getValue()="0"
		and target_11.getArgument(2).(VariableAccess).getTarget()=vent_7121
		and target_11.getArgument(3).(PointerFieldAccess).getTarget().getName()="sizeentcopy"
		and target_11.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_7120
}

from Function func, Variable vent_7121, Parameter vctxt_7120, PointerFieldAccess target_4, PointerFieldAccess target_5, LogicalOrExpr target_6, ExprStmt target_7, FunctionCall target_8, LogicalOrExpr target_9, ExprStmt target_10, FunctionCall target_11
where
not func_0(vent_7121, vctxt_7120, target_6, target_7)
and not func_1(vent_7121, vctxt_7120, target_8)
and not func_2(vent_7121, vctxt_7120, target_9, target_10, target_11)
and func_4(vent_7121, vctxt_7120, target_4)
and func_5(vent_7121, vctxt_7120, target_5)
and func_6(vent_7121, vctxt_7120, target_6)
and func_7(vent_7121, vctxt_7120, target_7)
and func_8(vent_7121, vctxt_7120, target_8)
and func_9(vctxt_7120, target_9)
and func_10(vent_7121, target_10)
and func_11(vent_7121, vctxt_7120, target_11)
and vent_7121.getType().hasName("xmlEntityPtr")
and vctxt_7120.getType().hasName("xmlParserCtxtPtr")
and vent_7121.(LocalVariable).getFunction() = func
and vctxt_7120.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
