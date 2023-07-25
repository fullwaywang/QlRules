/**
 * @name wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-parse_VariantCol
 * @id cpp/wireshark/d443be449a52f95df5754adc39e1f3472fec2f03/parse-VariantCol
 * @description wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-epan/dissectors/packet-mswsp.c-parse_VariantCol CVE-2018-18227
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

predicate func_2(Variable vvt_type_5329, BlockStmt target_25, ExprStmt target_26, ExprStmt target_27) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vvt_type_5329
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_25
		and target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vtvb_5323, Parameter voffset_5323, Variable vtree_5325, ExprStmt target_28, ExprStmt target_29, ExprStmt target_27) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("proto_item *")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_5325
		and target_3.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_3.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_5323
		and target_3.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_5323
		and target_3.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_3.getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Unknown variant column type"
		and target_3.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_28.getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Function func) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_6.getParent().(FunctionCall).getParent().(ConditionalExpr).getElse() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vmodifier_5330, LogicalOrExpr target_16, ExprStmt target_27) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("except_throwf")
		and target_7.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unknown variant column type%s"
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmodifier_5330
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_27.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_8(Parameter voffset_5323, LogicalOrExpr target_16, ExprStmt target_30, ExprStmt target_28) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(VariableAccess).getTarget()=voffset_5323
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(VariableAccess).getLocation())
		and target_8.getExpr().(VariableAccess).getLocation().isBefore(target_28.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_10(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, Variable vvt_type_5329, Variable vsize_5331, Variable vstrbuf_5372, Variable vdesc_5375, Variable vhf_mswsp_rowvariant_item_value, Variable vlen_5385, ExprStmt target_31, ExprStmt target_32, SubExpr target_33, BitwiseAndExpr target_34, AddressOfExpr target_35, ExprStmt target_36, ExprStmt target_27, ExprStmt target_37, FunctionCall target_38, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition() instanceof LogicalOrExpr
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vvt_type_5329
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_5331
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="tvb_get"
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="strbuf_append"
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vstrbuf_5372
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_string_format_value")
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_5325
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_mswsp_rowvariant_item_value
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsize_5331
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vdesc_5375
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s: %s"
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vdesc_5375
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(FunctionCall).getTarget().hasName("wmem_strbuf_get_str")
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(5).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_64bit_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_5385
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="strbuf_append"
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vstrbuf_5372
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_5325
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_mswsp_rowvariant_item_value
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_5323
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vlen_5385
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(FunctionCall).getTarget().hasName("wmem_strbuf_get_str")
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_10)
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_32.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_33.getRightOperand().(VariableAccess).getLocation())
		and target_34.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation().isBefore(target_35.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_27.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation())
		and target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_10.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_38.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_15(Parameter voffset_5323, Function func, ExprStmt target_15) {
		target_15.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_5323
		and target_15.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Variable vvtype_high_5332, BlockStmt target_25, LogicalOrExpr target_16) {
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvtype_high_5332
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvtype_high_5332
		and target_16.getParent().(IfStmt).getThen()=target_25
}

predicate func_17(Variable vvt_type_5329, VariableAccess target_17) {
		target_17.getTarget()=vvt_type_5329
		and target_17.getParent().(NEExpr).getAnOperand() instanceof Literal
}

predicate func_18(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, VariableAccess target_18) {
		target_18.getTarget()=voffset_5323
		and target_18.getParent().(AssignExpr).getLValue() = target_18
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_18.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
}

/*predicate func_19(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, VariableAccess target_19) {
		target_19.getTarget()=vtvb_5323
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_19.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
}

*/
/*predicate func_20(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, VariableAccess target_20) {
		target_20.getTarget()=voffset_5323
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
}

*/
predicate func_21(Variable vvt_type_5329, ConditionalExpr target_21) {
		target_21.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvt_type_5329
		and target_21.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_21.getThen() instanceof Literal
		and target_21.getElse() instanceof FunctionCall
}

predicate func_22(Function func, FunctionCall target_22) {
		target_22.getTarget().hasName("wmem_packet_scope")
		and target_22.getEnclosingFunction() = func
}

predicate func_25(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, BlockStmt target_25) {
		target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_5323
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_25.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
}

predicate func_26(Parameter vvariant_5323, Variable vvt_type_5329, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvt_type_5329
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vType_get_type")
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vtype"
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
}

predicate func_27(Parameter vtvb_5323, Parameter voffset_5323, Variable vtree_5325, Variable vvt_type_5329, Variable vmodifier_5330, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_string_format_value")
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_5325
		and target_27.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_5323
		and target_27.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_5323
		and target_27.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_27.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="str"
		and target_27.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_type_5329
		and target_27.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s%s"
		and target_27.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="str"
		and target_27.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_type_5329
		and target_27.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vmodifier_5330
}

predicate func_28(Parameter vtvb_5323, Parameter voffset_5323, Parameter vvariant_5323, Variable vvt_type_5329, ExprStmt target_28) {
		target_28.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="tvb_get"
		and target_28.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_type_5329
		and target_28.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_28.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_28.getExpr().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_28.getExpr().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
}

predicate func_29(Parameter vtvb_5323, Parameter voffset_5323, Variable vtree_5325, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtree_5325
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_subtree")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_5323
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_5323
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_30(Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_5323
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_VariantColVector")
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_5325
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbase_address_5323
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vis_64bit_5323
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vvariant_5323
}

predicate func_31(Parameter vtvb_5323, Parameter voffset_5323, Parameter vvariant_5323, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="reserved2"
		and target_31.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_letohl")
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_5323
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_5323
}

predicate func_32(Parameter voffset_5323, ExprStmt target_32) {
		target_32.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_5323
		and target_32.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
}

predicate func_33(Parameter vbase_address_5323, SubExpr target_33) {
		target_33.getRightOperand().(VariableAccess).getTarget()=vbase_address_5323
}

predicate func_34(Parameter vvariant_5323, BitwiseAndExpr target_34) {
		target_34.getLeftOperand().(PointerFieldAccess).getTarget().getName()="vtype"
		and target_34.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
		and target_34.getRightOperand().(HexLiteral).getValue()="255"
}

predicate func_35(Parameter vvariant_5323, AddressOfExpr target_35) {
		target_35.getOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_35.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
}

predicate func_36(Parameter vtvb_5323, Parameter voffset_5323, Variable vtree_5325, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_5325
		and target_36.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_5323
		and target_36.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_5323
		and target_36.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_36.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="2147483648"
}

predicate func_37(Parameter vvariant_5323, Variable vsize_5331, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_5331
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_fixed_vtype_dataize")
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vtype"
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvariant_5323
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255"
}

predicate func_38(Variable vstrbuf_5372, FunctionCall target_38) {
		target_38.getTarget().hasName("wmem_strbuf_get_str")
		and target_38.getArgument(0).(VariableAccess).getTarget()=vstrbuf_5372
}

from Function func, Parameter vtvb_5323, Parameter voffset_5323, Parameter vbase_address_5323, Parameter vis_64bit_5323, Parameter vvariant_5323, Variable vtree_5325, Variable vvt_type_5329, Variable vmodifier_5330, Variable vsize_5331, Variable vvtype_high_5332, Variable vstrbuf_5372, Variable vdesc_5375, Variable vhf_mswsp_rowvariant_item_value, Variable vlen_5385, FunctionCall target_0, ExprStmt target_15, LogicalOrExpr target_16, VariableAccess target_17, VariableAccess target_18, ConditionalExpr target_21, FunctionCall target_22, BlockStmt target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32, SubExpr target_33, BitwiseAndExpr target_34, AddressOfExpr target_35, ExprStmt target_36, ExprStmt target_37, FunctionCall target_38
where
func_0(func, target_0)
and not func_2(vvt_type_5329, target_25, target_26, target_27)
and not func_3(vtvb_5323, voffset_5323, vtree_5325, target_28, target_29, target_27)
and not func_6(func)
and not func_7(vmodifier_5330, target_16, target_27)
and not func_8(voffset_5323, target_16, target_30, target_28)
and not func_10(vtvb_5323, voffset_5323, vbase_address_5323, vis_64bit_5323, vvariant_5323, vtree_5325, vvt_type_5329, vsize_5331, vstrbuf_5372, vdesc_5375, vhf_mswsp_rowvariant_item_value, vlen_5385, target_31, target_32, target_33, target_34, target_35, target_36, target_27, target_37, target_38, func)
and func_15(voffset_5323, func, target_15)
and func_16(vvtype_high_5332, target_25, target_16)
and func_17(vvt_type_5329, target_17)
and func_18(vtvb_5323, voffset_5323, vbase_address_5323, vis_64bit_5323, vvariant_5323, vtree_5325, target_18)
and func_21(vvt_type_5329, target_21)
and func_22(func, target_22)
and func_25(vtvb_5323, voffset_5323, vbase_address_5323, vis_64bit_5323, vvariant_5323, vtree_5325, target_25)
and func_26(vvariant_5323, vvt_type_5329, target_26)
and func_27(vtvb_5323, voffset_5323, vtree_5325, vvt_type_5329, vmodifier_5330, target_27)
and func_28(vtvb_5323, voffset_5323, vvariant_5323, vvt_type_5329, target_28)
and func_29(vtvb_5323, voffset_5323, vtree_5325, target_29)
and func_30(vtvb_5323, voffset_5323, vbase_address_5323, vis_64bit_5323, vvariant_5323, vtree_5325, target_30)
and func_31(vtvb_5323, voffset_5323, vvariant_5323, target_31)
and func_32(voffset_5323, target_32)
and func_33(vbase_address_5323, target_33)
and func_34(vvariant_5323, target_34)
and func_35(vvariant_5323, target_35)
and func_36(vtvb_5323, voffset_5323, vtree_5325, target_36)
and func_37(vvariant_5323, vsize_5331, target_37)
and func_38(vstrbuf_5372, target_38)
and vtvb_5323.getType().hasName("tvbuff_t *")
and voffset_5323.getType().hasName("int")
and vbase_address_5323.getType().hasName("guint64")
and vis_64bit_5323.getType().hasName("gboolean")
and vvariant_5323.getType().hasName("CRowVariant *")
and vtree_5325.getType().hasName("proto_tree *")
and vvt_type_5329.getType().hasName("vtype_data *")
and vmodifier_5330.getType().hasName("const char *")
and vsize_5331.getType().hasName("int")
and vvtype_high_5332.getType().hasName("guint16")
and vstrbuf_5372.getType().hasName("wmem_strbuf_t *")
and vdesc_5375.getType().hasName("const char *")
and vhf_mswsp_rowvariant_item_value.getType().hasName("int")
and vlen_5385.getType().hasName("int")
and vtvb_5323.getParentScope+() = func
and voffset_5323.getParentScope+() = func
and vbase_address_5323.getParentScope+() = func
and vis_64bit_5323.getParentScope+() = func
and vvariant_5323.getParentScope+() = func
and vtree_5325.getParentScope+() = func
and vvt_type_5329.getParentScope+() = func
and vmodifier_5330.getParentScope+() = func
and vsize_5331.getParentScope+() = func
and vvtype_high_5332.getParentScope+() = func
and vstrbuf_5372.getParentScope+() = func
and vdesc_5375.getParentScope+() = func
and not vhf_mswsp_rowvariant_item_value.getParentScope+() = func
and vlen_5385.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
