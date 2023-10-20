/**
 * @name wireshark-11f40896b696e4e8c7f8b2ad96028404a83a51a4-dissect_eventdata_cmd
 * @id cpp/wireshark/11f40896b696e4e8c7f8b2ad96028404a83a51a4/dissect-eventdata-cmd
 * @description wireshark-11f40896b696e4e8c7f8b2ad96028404a83a51a4-epan/dissectors/packet-gvcp.c-dissect_eventdata_cmd CVE-2020-15466
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtvb_2002, Parameter vextendedblockids_2002, Variable voffset_2005, Variable vdata_length_2006, Variable vhf_gvcp_eventcmd_extid_length, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, IfStmt target_0) {
		target_0.getCondition().(VariableAccess).getTarget()=vextendedblockids_2002
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_extid_length
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_length_2006
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2002
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_2005
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_1(Variable voffset_2005, EqualityOperation target_11, ExprStmt target_1) {
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_1.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_2(Parameter vtvb_2002, Variable veventid_2004, Variable voffset_2005, Variable vhf_gvcp_eventcmd_id, Variable vhf_gvcp_eventcmd_error_id, Variable vhf_gvcp_eventcmd_device_specific_id, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, IfStmt target_2) {
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="0"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="32768"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_id
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="32769"
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="36863"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_error_id
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="36864"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=veventid_2004
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="65535"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_device_specific_id
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_2.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_3(Variable voffset_2005, EqualityOperation target_11, ExprStmt target_3) {
		target_3.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_3.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Parameter vtvb_2002, Variable voffset_2005, Variable vhf_gvcp_eventcmd_stream_channel_index, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_stream_channel_index
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_4.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_4.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(Variable voffset_2005, EqualityOperation target_11, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_5.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_6(Parameter vtvb_2002, Parameter vextendedblockids_2002, Variable voffset_2005, Variable vhf_gvcp_eventcmd_block_id, Variable vhf_gvcp_eventcmd_block_id_64bit_v2_0, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vextendedblockids_2002
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_block_id
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_block_id_64bit_v2_0
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="8"
		and target_6.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_6.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_6.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_7(Parameter vtvb_2002, Variable voffset_2005, Variable vhf_gvcp_eventcmd_timestamp, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_timestamp
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_7.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="8"
		and target_7.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_8(Variable voffset_2005, EqualityOperation target_11, ExprStmt target_8) {
		target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_8.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_9(Parameter vtvb_2002, Parameter vextendedblockids_2002, Variable voffset_2005, Variable vdata_length_2006, Variable vhf_gvcp_eventcmd_data, Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11, IfStmt target_9) {
		target_9.getCondition().(VariableAccess).getTarget()=vextendedblockids_2002
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_length_2006
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="24"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_data
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_2005
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_gvcp_eventcmd_data
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2002
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_2005
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_9.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_9.getElse().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_10(Parameter vgvcp_telegram_tree_2002, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_10.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_10.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(6) instanceof IfStmt
		and target_10.getThen().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(9) instanceof IfStmt
}

predicate func_11(Parameter vgvcp_telegram_tree_2002, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vgvcp_telegram_tree_2002
		and target_11.getAnOperand() instanceof Literal
}

from Function func, Parameter vtvb_2002, Parameter vextendedblockids_2002, Variable veventid_2004, Variable voffset_2005, Variable vdata_length_2006, Variable vhf_gvcp_eventcmd_extid_length, Variable vhf_gvcp_eventcmd_id, Variable vhf_gvcp_eventcmd_error_id, Variable vhf_gvcp_eventcmd_device_specific_id, Variable vhf_gvcp_eventcmd_stream_channel_index, Variable vhf_gvcp_eventcmd_block_id, Variable vhf_gvcp_eventcmd_block_id_64bit_v2_0, Variable vhf_gvcp_eventcmd_timestamp, Variable vhf_gvcp_eventcmd_data, Parameter vgvcp_telegram_tree_2002, IfStmt target_0, ExprStmt target_1, IfStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, IfStmt target_6, ExprStmt target_7, ExprStmt target_8, IfStmt target_9, IfStmt target_10, EqualityOperation target_11
where
func_0(vtvb_2002, vextendedblockids_2002, voffset_2005, vdata_length_2006, vhf_gvcp_eventcmd_extid_length, vgvcp_telegram_tree_2002, target_11, target_0)
and func_1(voffset_2005, target_11, target_1)
and func_2(vtvb_2002, veventid_2004, voffset_2005, vhf_gvcp_eventcmd_id, vhf_gvcp_eventcmd_error_id, vhf_gvcp_eventcmd_device_specific_id, vgvcp_telegram_tree_2002, target_11, target_2)
and func_3(voffset_2005, target_11, target_3)
and func_4(vtvb_2002, voffset_2005, vhf_gvcp_eventcmd_stream_channel_index, vgvcp_telegram_tree_2002, target_11, target_4)
and func_5(voffset_2005, target_11, target_5)
and func_6(vtvb_2002, vextendedblockids_2002, voffset_2005, vhf_gvcp_eventcmd_block_id, vhf_gvcp_eventcmd_block_id_64bit_v2_0, vgvcp_telegram_tree_2002, target_11, target_6)
and func_7(vtvb_2002, voffset_2005, vhf_gvcp_eventcmd_timestamp, vgvcp_telegram_tree_2002, target_11, target_7)
and func_8(voffset_2005, target_11, target_8)
and func_9(vtvb_2002, vextendedblockids_2002, voffset_2005, vdata_length_2006, vhf_gvcp_eventcmd_data, vgvcp_telegram_tree_2002, target_11, target_9)
and func_10(vgvcp_telegram_tree_2002, target_10)
and func_11(vgvcp_telegram_tree_2002, target_11)
and vtvb_2002.getType().hasName("tvbuff_t *")
and vextendedblockids_2002.getType().hasName("gint")
and veventid_2004.getType().hasName("gint32")
and voffset_2005.getType().hasName("gint")
and vdata_length_2006.getType().hasName("gint")
and vhf_gvcp_eventcmd_extid_length.getType().hasName("int")
and vhf_gvcp_eventcmd_id.getType().hasName("int")
and vhf_gvcp_eventcmd_error_id.getType().hasName("int")
and vhf_gvcp_eventcmd_device_specific_id.getType().hasName("int")
and vhf_gvcp_eventcmd_stream_channel_index.getType().hasName("int")
and vhf_gvcp_eventcmd_block_id.getType().hasName("int")
and vhf_gvcp_eventcmd_block_id_64bit_v2_0.getType().hasName("int")
and vhf_gvcp_eventcmd_timestamp.getType().hasName("int")
and vhf_gvcp_eventcmd_data.getType().hasName("int")
and vgvcp_telegram_tree_2002.getType().hasName("proto_tree *")
and vtvb_2002.getParentScope+() = func
and vextendedblockids_2002.getParentScope+() = func
and veventid_2004.getParentScope+() = func
and voffset_2005.getParentScope+() = func
and vdata_length_2006.getParentScope+() = func
and not vhf_gvcp_eventcmd_extid_length.getParentScope+() = func
and not vhf_gvcp_eventcmd_id.getParentScope+() = func
and not vhf_gvcp_eventcmd_error_id.getParentScope+() = func
and not vhf_gvcp_eventcmd_device_specific_id.getParentScope+() = func
and not vhf_gvcp_eventcmd_stream_channel_index.getParentScope+() = func
and not vhf_gvcp_eventcmd_block_id.getParentScope+() = func
and not vhf_gvcp_eventcmd_block_id_64bit_v2_0.getParentScope+() = func
and not vhf_gvcp_eventcmd_timestamp.getParentScope+() = func
and not vhf_gvcp_eventcmd_data.getParentScope+() = func
and vgvcp_telegram_tree_2002.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
