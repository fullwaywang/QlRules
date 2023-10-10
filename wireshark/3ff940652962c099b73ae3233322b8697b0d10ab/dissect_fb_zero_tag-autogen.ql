/**
 * @name wireshark-3ff940652962c099b73ae3233322b8697b0d10ab-dissect_fb_zero_tag
 * @id cpp/wireshark/3ff940652962c099b73ae3233322b8697b0d10ab/dissect-fb-zero-tag
 * @description wireshark-3ff940652962c099b73ae3233322b8697b0d10ab-epan/dissectors/packet-fbzero.c-dissect_fb_zero_tag CVE-2020-26575
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtag_offset_161, Variable voffset_end_166, SubExpr target_8, VariableAccess target_0) {
		target_0.getTarget()=voffset_end_166
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtag_offset_161
		and target_8.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_1(VariableAccess target_9, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="end"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_9
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(EqualityOperation target_10, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="end"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_2.getEnclosingFunction() = func)
}

predicate func_4(Parameter vfb_zero_tree_159, Parameter vtvb_159, Parameter vpinfo_159, Parameter voffset_159, Variable vtotal_tag_len_161, ExprStmt target_11, ExprStmt target_12, SubExpr target_13, AddExpr target_14, ExprStmt target_15, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_159
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("guint32")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_159
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_159
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfb_zero_tree_159
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid total tag length: %u"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtotal_tag_len_161
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_159
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_159
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_159
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_4)
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

/*predicate func_5(Parameter vfb_zero_tree_159, Parameter vpinfo_159, Variable vtotal_tag_len_161, ExprStmt target_11, ExprStmt target_12, ExprStmt target_15, AddExpr target_14) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("expert_add_info_format")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vpinfo_159
		and target_5.getArgument(1).(VariableAccess).getTarget()=vfb_zero_tree_159
		and target_5.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_5.getArgument(3).(StringLiteral).getValue()="Invalid total tag length: %u"
		and target_5.getArgument(4).(VariableAccess).getTarget()=vtotal_tag_len_161
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getArgument(1).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getArgument(4).(VariableAccess).getLocation())
		and target_5.getArgument(4).(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_6(Variable vtag_offset_161, Variable vtag_len_162, VariableAccess target_9, AddExpr target_16, EqualityOperation target_10, ExprStmt target_17, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vtag_offset_161
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vtag_len_162
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_9
		and target_16.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(VariableAccess).getLocation())
		and target_17.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_7(Variable vtag_offset_161, Variable voffset_end_166, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vtag_offset_161
		and target_7.getRValue().(VariableAccess).getTarget()=voffset_end_166
}

predicate func_8(Variable vtag_offset_161, Variable voffset_end_166, SubExpr target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=voffset_end_166
		and target_8.getRightOperand().(VariableAccess).getTarget()=vtag_offset_161
}

predicate func_9(Variable vtag_166, VariableAccess target_9) {
		target_9.getTarget()=vtag_166
}

predicate func_10(Variable vtag_offset_161, Variable voffset_end_166, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vtag_offset_161
		and target_10.getAnOperand().(VariableAccess).getTarget()=voffset_end_166
}

predicate func_11(Parameter vfb_zero_tree_159, Parameter vtvb_159, Parameter voffset_159, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfb_zero_tree_159
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_159
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_159
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="8"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_12(Parameter vtvb_159, Parameter vpinfo_159, Variable vtag_offset_161, Variable voffset_end_166, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_expert")
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_159
		and target_12.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_159
		and target_12.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtag_offset_161
		and target_12.getExpr().(FunctionCall).getArgument(5).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffset_end_166
		and target_12.getExpr().(FunctionCall).getArgument(5).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vtag_offset_161
}

predicate func_13(Parameter voffset_159, SubExpr target_13) {
		target_13.getLeftOperand().(VariableAccess).getTarget()=voffset_159
		and target_13.getRightOperand().(Literal).getValue()="8"
}

predicate func_14(Parameter voffset_159, Variable vtotal_tag_len_161, AddExpr target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=voffset_159
		and target_14.getAnOperand().(VariableAccess).getTarget()=vtotal_tag_len_161
}

predicate func_15(Variable vtotal_tag_len_161, Variable vtag_len_162, ExprStmt target_15) {
		target_15.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vtotal_tag_len_161
		and target_15.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vtag_len_162
}

predicate func_16(Variable vtag_offset_161, AddExpr target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vtag_offset_161
}

predicate func_17(Parameter vtvb_159, Variable vtag_offset_161, Variable vtag_len_162, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_17.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_159
		and target_17.getExpr().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtag_offset_161
		and target_17.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtag_len_162
		and target_17.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

from Function func, Parameter vfb_zero_tree_159, Parameter vtvb_159, Parameter vpinfo_159, Parameter voffset_159, Variable vtag_offset_161, Variable vtotal_tag_len_161, Variable vtag_len_162, Variable voffset_end_166, Variable vtag_166, VariableAccess target_0, ExprStmt target_6, AssignExpr target_7, SubExpr target_8, VariableAccess target_9, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12, SubExpr target_13, AddExpr target_14, ExprStmt target_15, AddExpr target_16, ExprStmt target_17
where
func_0(vtag_offset_161, voffset_end_166, target_8, target_0)
and not func_1(target_9, func)
and not func_2(target_10, func)
and not func_4(vfb_zero_tree_159, vtvb_159, vpinfo_159, voffset_159, vtotal_tag_len_161, target_11, target_12, target_13, target_14, target_15, func)
and func_6(vtag_offset_161, vtag_len_162, target_9, target_16, target_10, target_17, target_6)
and func_7(vtag_offset_161, voffset_end_166, target_7)
and func_8(vtag_offset_161, voffset_end_166, target_8)
and func_9(vtag_166, target_9)
and func_10(vtag_offset_161, voffset_end_166, target_10)
and func_11(vfb_zero_tree_159, vtvb_159, voffset_159, target_11)
and func_12(vtvb_159, vpinfo_159, vtag_offset_161, voffset_end_166, target_12)
and func_13(voffset_159, target_13)
and func_14(voffset_159, vtotal_tag_len_161, target_14)
and func_15(vtotal_tag_len_161, vtag_len_162, target_15)
and func_16(vtag_offset_161, target_16)
and func_17(vtvb_159, vtag_offset_161, vtag_len_162, target_17)
and vfb_zero_tree_159.getType().hasName("proto_tree *")
and vtvb_159.getType().hasName("tvbuff_t *")
and vpinfo_159.getType().hasName("packet_info *")
and voffset_159.getType().hasName("guint")
and vtag_offset_161.getType().hasName("guint32")
and vtotal_tag_len_161.getType().hasName("guint32")
and vtag_len_162.getType().hasName("gint32")
and voffset_end_166.getType().hasName("guint32")
and vtag_166.getType().hasName("guint32")
and vfb_zero_tree_159.getParentScope+() = func
and vtvb_159.getParentScope+() = func
and vpinfo_159.getParentScope+() = func
and voffset_159.getParentScope+() = func
and vtag_offset_161.getParentScope+() = func
and vtotal_tag_len_161.getParentScope+() = func
and vtag_len_162.getParentScope+() = func
and voffset_end_166.getParentScope+() = func
and vtag_166.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
