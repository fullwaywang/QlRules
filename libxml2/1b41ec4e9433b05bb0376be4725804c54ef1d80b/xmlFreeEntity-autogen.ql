/**
 * @name libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlFreeEntity
 * @id cpp/libxml2/1b41ec4e9433b05bb0376be4725804c54ef1d80b/xmlFreeEntity
 * @description libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlFreeEntity CVE-2022-40304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_1(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(NotExpr target_1 |
		target_1.getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_1.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_2(Parameter ventity_117, Variable vxmlFree) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_3(Parameter ventity_117) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="ExternalID"
		and target_3.getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_3.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_4(Parameter ventity_117, Variable vxmlFree) {
	exists(EqualityOperation target_4 |
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_4.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_5(Parameter ventity_117) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="SystemID"
		and target_5.getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_5.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_6(Parameter ventity_117, Variable vxmlFree) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="URI"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_6.getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="URI"
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_7(Parameter ventity_117) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="URI"
		and target_7.getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_7.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_8(Parameter ventity_117, Variable vxmlFree) {
	exists(EqualityOperation target_8 |
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_8.getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_9(Parameter ventity_117) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="content"
		and target_9.getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_9.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_10(Parameter ventity_117, Variable vxmlFree) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="orig"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_10.getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orig"
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117)
}

predicate func_11(Parameter ventity_117) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="orig"
		and target_11.getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall)
}

predicate func_12(Parameter ventity_117, Variable vxmlFree) {
	exists(IfStmt target_12 |
		target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_12.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_12.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_13(Parameter ventity_117, Variable vxmlFree) {
	exists(IfStmt target_13 |
		target_13.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_13.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_13.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_14(Parameter ventity_117, Variable vxmlFree) {
	exists(IfStmt target_14 |
		target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="URI"
		and target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_14.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="URI"
		and target_14.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_15(Parameter ventity_117, Variable vxmlFree) {
	exists(IfStmt target_15 |
		target_15.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_15.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_15.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_16(Parameter ventity_117, Variable vxmlFree) {
	exists(IfStmt target_16 |
		target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="orig"
		and target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_16.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orig"
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_18(Function func) {
	exists(Literal target_18 |
		target_18.getValue()="0"
		and target_18.getEnclosingFunction() = func)
}

predicate func_22(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(IfStmt target_22 |
		target_22.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_22.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_22.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_22.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_22.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal)
}

predicate func_23(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(IfStmt target_23 |
		target_23.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_23.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_23.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_23.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_23.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_23.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="URI"
		and target_23.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal)
}

predicate func_24(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(IfStmt target_24 |
		target_24.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_24.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_24.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_24.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_24.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_24.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_24.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal)
}

predicate func_25(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(IfStmt target_25 |
		target_25.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_25.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_25.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_25.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orig"
		and target_25.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_25.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal)
}

predicate func_26(Parameter ventity_117, Variable vdict_119, Variable vxmlFree) {
	exists(IfStmt target_26 |
		target_26.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_26.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_26.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_26.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_26.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_26.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal)
}

from Function func, Parameter ventity_117, Variable vdict_119, Variable vxmlFree
where
not func_0(ventity_117, vdict_119, vxmlFree)
and func_1(ventity_117, vdict_119, vxmlFree)
and func_2(ventity_117, vxmlFree)
and func_3(ventity_117)
and func_4(ventity_117, vxmlFree)
and func_5(ventity_117)
and func_6(ventity_117, vxmlFree)
and func_7(ventity_117)
and func_8(ventity_117, vxmlFree)
and func_9(ventity_117)
and func_10(ventity_117, vxmlFree)
and func_11(ventity_117)
and func_12(ventity_117, vxmlFree)
and func_13(ventity_117, vxmlFree)
and func_14(ventity_117, vxmlFree)
and func_15(ventity_117, vxmlFree)
and func_16(ventity_117, vxmlFree)
and func_18(func)
and func_22(ventity_117, vdict_119, vxmlFree)
and func_23(ventity_117, vdict_119, vxmlFree)
and func_24(ventity_117, vdict_119, vxmlFree)
and func_25(ventity_117, vdict_119, vxmlFree)
and func_26(ventity_117, vdict_119, vxmlFree)
and ventity_117.getType().hasName("xmlEntityPtr")
and vdict_119.getType().hasName("xmlDictPtr")
and vxmlFree.getType().hasName("xmlFreeFunc")
and ventity_117.getParentScope+() = func
and vdict_119.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
