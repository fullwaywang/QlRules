/**
 * @name wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-parse_CBaseStorageVariant
 * @id cpp/wireshark/d443be449a52f95df5754adc39e1f3472fec2f03/parse-CBaseStorageVariant
 * @description wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-epan/dissectors/packet-mswsp.c-parse_CBaseStorageVariant CVE-2018-18227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("proto_report_dissector_bug")
		and not target_0.getTarget().hasName("expert_add_info")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("wmem_strdup_printf")
		and target_0.getArgument(0).(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_0.getArgument(0).(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getArgument(0).(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_0.getArgument(0).(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getArgument(0).(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vvalue_4314, Parameter vtvb_4314, Parameter voffset_4314, PointerDereferenceExpr target_22, ExprStmt target_23, ExprStmt target_24) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="vType"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_1.getRValue().(FunctionCall).getTarget().hasName("tvb_get_letohs")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_4314
		and target_1.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_4314
		and target_22.getOperand().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vvalue_4314, ExprStmt target_23) {
	exists(BitwiseAndExpr target_2 |
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="vType"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_2.getRightOperand().(HexLiteral).getValue()="255"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vType_get_type")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vType"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vvalue_4314, Variable vti_type_4317, Variable vtree_4318, Parameter vtvb_4314, Parameter voffset_4314, ExprStmt target_23, PointerFieldAccess target_26, ExprStmt target_24, ExprStmt target_27, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vti_type_4317
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_4318
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_4314
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_4314
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Unknown CBaseStorageVariant type"
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("packet_info *")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vti_type_4317
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("except_throw")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown CBaseStorageVariant type"
		and target_3.getThen().(BlockStmt).getStmt(4) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3)
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vti_type_4317, Variable vtree_4318, Parameter vtvb_4314, Parameter voffset_4314, ExprStmt target_24, ExprStmt target_27) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vti_type_4317
		and target_4.getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_4318
		and target_4.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_4.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_4314
		and target_4.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_4314
		and target_4.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_4.getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Unknown CBaseStorageVariant type"
		and target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_7(Function func) {
	exists(AddressOfExpr target_7 |
		target_7.getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_7.getParent().(FunctionCall).getParent().(ConditionalExpr).getElse() instanceof FunctionCall
		and target_7.getEnclosingFunction() = func)
}

*/
predicate func_8(Parameter voffset_4314, ExprStmt target_27, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_4314
		and target_8.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_8)
		and target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_9(Parameter voffset_4314, ExprStmt target_32, ReturnStmt target_12, Function func) {
	exists(ReturnStmt target_9 |
		target_9.getExpr().(VariableAccess).getTarget()=voffset_4314
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_9)
		and target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_9.getExpr().(VariableAccess).getLocation())
		and target_9.getExpr().(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vvalue_4314, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="type"
		and target_10.getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_10.getParent().(NEExpr).getAnOperand() instanceof Literal
}

predicate func_11(Parameter voffset_4314, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_4314
		and target_11.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter voffset_4314, Function func, ReturnStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=voffset_4314
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vvalue_4314, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="vType"
		and target_13.getQualifier().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_14(Parameter vvalue_4314, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="vType"
		and target_14.getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vType_get_type")
}

predicate func_15(Parameter vtvb_4314, VariableAccess target_15) {
		target_15.getTarget()=vtvb_4314
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_16(Parameter voffset_4314, VariableAccess target_16) {
		target_16.getTarget()=voffset_4314
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_17(Parameter vvalue_4314, Parameter vtvb_4314, Parameter voffset_4314, FunctionCall target_17) {
		target_17.getTarget().hasName("parse_vType")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vtvb_4314
		and target_17.getArgument(1).(VariableAccess).getTarget()=voffset_4314
		and target_17.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vType"
		and target_17.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_18(Parameter vvalue_4314, ConditionalExpr target_18) {
		target_18.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_18.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_18.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_18.getThen() instanceof Literal
		and target_18.getElse() instanceof FunctionCall
}

predicate func_19(Function func, FunctionCall target_19) {
		target_19.getTarget().hasName("wmem_packet_scope")
		and target_19.getEnclosingFunction() = func
}

predicate func_22(Parameter vvalue_4314, PointerDereferenceExpr target_22) {
		target_22.getOperand().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_23(Parameter vvalue_4314, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vType_get_type")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vType"
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_24(Variable vtree_4318, Parameter vtvb_4314, Parameter voffset_4314, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtree_4318
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_subtree")
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_4314
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_4314
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_26(Parameter vvalue_4314, PointerFieldAccess target_26) {
		target_26.getTarget().getName()="str"
		and target_26.getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_26.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_27(Parameter vvalue_4314, Variable vti_type_4317, Variable vtree_4318, Parameter vtvb_4314, Parameter voffset_4314, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vti_type_4317
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_4318
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_4314
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_4314
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="str"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_4314
}

predicate func_32(Parameter vtvb_4314, Parameter voffset_4314, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("proto_item_set_end")
		and target_32.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_4314
		and target_32.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_4314
}

from Function func, Parameter vvalue_4314, Variable vti_type_4317, Variable vtree_4318, Parameter vtvb_4314, Parameter voffset_4314, FunctionCall target_0, PointerFieldAccess target_10, ExprStmt target_11, ReturnStmt target_12, PointerFieldAccess target_13, PointerFieldAccess target_14, VariableAccess target_15, VariableAccess target_16, FunctionCall target_17, ConditionalExpr target_18, FunctionCall target_19, PointerDereferenceExpr target_22, ExprStmt target_23, ExprStmt target_24, PointerFieldAccess target_26, ExprStmt target_27, ExprStmt target_32
where
func_0(func, target_0)
and not func_1(vvalue_4314, vtvb_4314, voffset_4314, target_22, target_23, target_24)
and not func_2(vvalue_4314, target_23)
and not func_3(vvalue_4314, vti_type_4317, vtree_4318, vtvb_4314, voffset_4314, target_23, target_26, target_24, target_27, func)
and not func_8(voffset_4314, target_27, func)
and not func_9(voffset_4314, target_32, target_12, func)
and func_10(vvalue_4314, target_10)
and func_11(voffset_4314, func, target_11)
and func_12(voffset_4314, func, target_12)
and func_13(vvalue_4314, target_13)
and func_14(vvalue_4314, target_14)
and func_15(vtvb_4314, target_15)
and func_16(voffset_4314, target_16)
and func_17(vvalue_4314, vtvb_4314, voffset_4314, target_17)
and func_18(vvalue_4314, target_18)
and func_19(func, target_19)
and func_22(vvalue_4314, target_22)
and func_23(vvalue_4314, target_23)
and func_24(vtree_4318, vtvb_4314, voffset_4314, target_24)
and func_26(vvalue_4314, target_26)
and func_27(vvalue_4314, vti_type_4317, vtree_4318, vtvb_4314, voffset_4314, target_27)
and func_32(vtvb_4314, voffset_4314, target_32)
and vvalue_4314.getType().hasName("CBaseStorageVariant *")
and vti_type_4317.getType().hasName("proto_item *")
and vtree_4318.getType().hasName("proto_tree *")
and vtvb_4314.getType().hasName("tvbuff_t *")
and voffset_4314.getType().hasName("int")
and vvalue_4314.getParentScope+() = func
and vti_type_4317.getParentScope+() = func
and vtree_4318.getParentScope+() = func
and vtvb_4314.getParentScope+() = func
and voffset_4314.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
