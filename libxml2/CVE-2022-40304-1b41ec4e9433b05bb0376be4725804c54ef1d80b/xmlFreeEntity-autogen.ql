/**
 * @name libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-xmlFreeEntity
 * @id cpp/libxml2/1b41ec4e9433b05bb0376be4725804c54ef1d80b/xmlFreeEntity
 * @description libxml2-1b41ec4e9433b05bb0376be4725804c54ef1d80b-entities.c-xmlFreeEntity CVE-2022-40304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter ventity_117, Variable vdict_119, ExprStmt target_22, ExprStmt target_23) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_0.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_22
		and target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter ventity_117, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="ExternalID"
		and target_1.getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_2(Parameter ventity_117, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="SystemID"
		and target_2.getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_3(Parameter ventity_117, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="URI"
		and target_3.getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_4(Parameter ventity_117, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="content"
		and target_4.getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_5(Parameter ventity_117, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="orig"
		and target_5.getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_6(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_6.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_7(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_7.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_7.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_8(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="URI"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_8.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="URI"
		and target_8.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_9(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_9.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_10(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="orig"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_10.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orig"
		and target_10.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_11(Parameter ventity_117, Variable vdict_119, ExprStmt target_22, NotExpr target_11) {
		target_11.getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_11.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_11.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_22
}

predicate func_12(Variable vdict_119, BlockStmt target_25, VariableAccess target_12) {
		target_12.getTarget()=vdict_119
		and target_12.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_25
}

predicate func_14(Variable vdict_119, BlockStmt target_25, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vdict_119
		and target_14.getAnOperand() instanceof Literal
		and target_14.getParent().(IfStmt).getThen()=target_25
}

predicate func_15(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_15) {
		target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getCondition().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_15.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_16(Parameter ventity_117, Variable vdict_119, Variable vxmlFree, EqualityOperation target_14, IfStmt target_16) {
		target_16.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_16.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ExternalID"
		and target_16.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_17(Parameter ventity_117, Variable vdict_119, Variable vxmlFree, EqualityOperation target_14, IfStmt target_17) {
		target_17.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_17.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_17.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_17.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="SystemID"
		and target_17.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_18(Parameter ventity_117, Variable vdict_119, Variable vxmlFree, EqualityOperation target_14, IfStmt target_18) {
		target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="URI"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="URI"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_18.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_18.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="URI"
		and target_18.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_19(Parameter ventity_117, Variable vdict_119, Variable vxmlFree, EqualityOperation target_14, IfStmt target_19) {
		target_19.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_19.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_19.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_19.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_19.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_20(Parameter ventity_117, Variable vdict_119, Variable vxmlFree, EqualityOperation target_14, IfStmt target_20) {
		target_20.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="orig"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlDictOwns")
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdict_119
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="orig"
		and target_20.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orig"
		and target_20.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_21(Parameter ventity_117, Variable vxmlFree, EqualityOperation target_14, IfStmt target_21) {
		target_21.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_21.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_21.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_21.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_21.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_21.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_22(Parameter ventity_117, Variable vxmlFree, ExprStmt target_22) {
		target_22.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_22.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_22.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_23(Parameter ventity_117, Variable vdict_119, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdict_119
		and target_23.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="dict"
		and target_23.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="doc"
		and target_23.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventity_117
}

predicate func_25(BlockStmt target_25) {
		target_25.getStmt(0) instanceof IfStmt
		and target_25.getStmt(1) instanceof IfStmt
		and target_25.getStmt(2) instanceof IfStmt
		and target_25.getStmt(3) instanceof IfStmt
		and target_25.getStmt(4) instanceof IfStmt
}

from Function func, Parameter ventity_117, Variable vdict_119, Variable vxmlFree, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, IfStmt target_6, IfStmt target_7, IfStmt target_8, IfStmt target_9, IfStmt target_10, NotExpr target_11, VariableAccess target_12, EqualityOperation target_14, IfStmt target_15, IfStmt target_16, IfStmt target_17, IfStmt target_18, IfStmt target_19, IfStmt target_20, IfStmt target_21, ExprStmt target_22, ExprStmt target_23, BlockStmt target_25
where
not func_0(ventity_117, vdict_119, target_22, target_23)
and func_1(ventity_117, target_1)
and func_2(ventity_117, target_2)
and func_3(ventity_117, target_3)
and func_4(ventity_117, target_4)
and func_5(ventity_117, target_5)
and func_6(ventity_117, vxmlFree, target_14, target_6)
and func_7(ventity_117, vxmlFree, target_14, target_7)
and func_8(ventity_117, vxmlFree, target_14, target_8)
and func_9(ventity_117, vxmlFree, target_14, target_9)
and func_10(ventity_117, vxmlFree, target_14, target_10)
and func_11(ventity_117, vdict_119, target_22, target_11)
and func_12(vdict_119, target_25, target_12)
and func_14(vdict_119, target_25, target_14)
and func_15(ventity_117, vxmlFree, target_14, target_15)
and func_16(ventity_117, vdict_119, vxmlFree, target_14, target_16)
and func_17(ventity_117, vdict_119, vxmlFree, target_14, target_17)
and func_18(ventity_117, vdict_119, vxmlFree, target_14, target_18)
and func_19(ventity_117, vdict_119, vxmlFree, target_14, target_19)
and func_20(ventity_117, vdict_119, vxmlFree, target_14, target_20)
and func_21(ventity_117, vxmlFree, target_14, target_21)
and func_22(ventity_117, vxmlFree, target_22)
and func_23(ventity_117, vdict_119, target_23)
and func_25(target_25)
and ventity_117.getType().hasName("xmlEntityPtr")
and vdict_119.getType().hasName("xmlDictPtr")
and vxmlFree.getType().hasName("xmlFreeFunc")
and ventity_117.getParentScope+() = func
and vdict_119.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
