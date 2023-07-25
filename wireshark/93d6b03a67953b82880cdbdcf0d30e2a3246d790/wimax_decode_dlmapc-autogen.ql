/**
 * @name wireshark-93d6b03a67953b82880cdbdcf0d30e2a3246d790-wimax_decode_dlmapc
 * @id cpp/wireshark/93d6b03a67953b82880cdbdcf0d30e2a3246d790/wimax-decode-dlmapc
 * @description wireshark-93d6b03a67953b82880cdbdcf0d30e2a3246d790-plugins/epan/wimax/msg_dlmap.c-wimax_decode_dlmapc CVE-2020-9430
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpinfo_2296, Variable vti_2302, Variable vmac_len_2310, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmac_len_2310
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_2296
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vti_2302
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Invalid length: %d."
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmac_len_2310
		and target_0.getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(37)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(37).getFollowingStmt()=target_0)
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpinfo_2296, Parameter vbase_tree_2296, Parameter vtvb_2296, Variable vmac_len_2310, Variable vtvb_len_2311, Variable vcalculated_crc_2313, Variable vproto_mac_mgmt_msg_dlmap_decoder, Variable vhf_mac_header_compress_dlmap_crc, Variable vhf_mac_header_compress_dlmap_crc_status, Variable vei_mac_header_compress_dlmap_crc, Function func, IfStmt target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtvb_len_2311
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2296
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vtvb_len_2311
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2296
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmac_len_2310
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcalculated_crc_2313
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wimax_mac_calc_crc32")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("tvb_get_ptr")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2296
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vmac_len_2310
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_checksum")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_tree_2296
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_2296
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vmac_len_2310
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhf_mac_header_compress_dlmap_crc
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhf_mac_header_compress_dlmap_crc_status
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vei_mac_header_compress_dlmap_crc
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vpinfo_2296
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vcalculated_crc_2313
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="1"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_protocol_format")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_tree_2296
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vproto_mac_mgmt_msg_dlmap_decoder
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_2296
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtvb_len_2311
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="CRC missing - the frame is too short (%u bytes)"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vtvb_len_2311
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vpinfo_2296, Parameter vbase_tree_2296, Parameter vtvb_2296, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("wimax_decode_ulmapc")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_tree_2296
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_2296
		and target_2.getExpr().(FunctionCall).getArgument(3).(SubExpr).getRightOperand().(Literal).getValue()="8"
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtvb_2296
}

predicate func_3(Parameter vpinfo_2296, Parameter vbase_tree_2296, Parameter vtvb_2296, Variable vmac_len_2310, Variable vcalculated_crc_2313, Variable vhf_mac_header_compress_dlmap_crc, Variable vhf_mac_header_compress_dlmap_crc_status, Variable vei_mac_header_compress_dlmap_crc, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_checksum")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_tree_2296
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_2296
		and target_3.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vmac_len_2310
		and target_3.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhf_mac_header_compress_dlmap_crc
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhf_mac_header_compress_dlmap_crc_status
		and target_3.getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vei_mac_header_compress_dlmap_crc
		and target_3.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vpinfo_2296
		and target_3.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vcalculated_crc_2313
		and target_3.getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="1"
}

predicate func_4(Variable vti_2302, Parameter vtvb_2296, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("proto_item_set_end")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vti_2302
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_2296
		and target_4.getExpr().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vmac_len_2310, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmac_len_2310
}

predicate func_6(Parameter vtvb_2296, Variable vmac_len_2310, Variable vtvb_len_2311, RelationalOperation target_6) {
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtvb_len_2311
		and target_6.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_6.getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2296
		and target_6.getGreaterOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vtvb_len_2311
		and target_6.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("tvb_reported_length")
		and target_6.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_2296
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vmac_len_2310
}

from Function func, Parameter vpinfo_2296, Parameter vbase_tree_2296, Variable vti_2302, Parameter vtvb_2296, Variable vmac_len_2310, Variable vtvb_len_2311, Variable vcalculated_crc_2313, Variable vproto_mac_mgmt_msg_dlmap_decoder, Variable vhf_mac_header_compress_dlmap_crc, Variable vhf_mac_header_compress_dlmap_crc_status, Variable vei_mac_header_compress_dlmap_crc, IfStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_0(vpinfo_2296, vti_2302, vmac_len_2310, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vpinfo_2296, vbase_tree_2296, vtvb_2296, vmac_len_2310, vtvb_len_2311, vcalculated_crc_2313, vproto_mac_mgmt_msg_dlmap_decoder, vhf_mac_header_compress_dlmap_crc, vhf_mac_header_compress_dlmap_crc_status, vei_mac_header_compress_dlmap_crc, func, target_1)
and func_2(vpinfo_2296, vbase_tree_2296, vtvb_2296, target_2)
and func_3(vpinfo_2296, vbase_tree_2296, vtvb_2296, vmac_len_2310, vcalculated_crc_2313, vhf_mac_header_compress_dlmap_crc, vhf_mac_header_compress_dlmap_crc_status, vei_mac_header_compress_dlmap_crc, target_3)
and func_4(vti_2302, vtvb_2296, target_4)
and func_5(vmac_len_2310, target_5)
and func_6(vtvb_2296, vmac_len_2310, vtvb_len_2311, target_6)
and vpinfo_2296.getType().hasName("packet_info *")
and vbase_tree_2296.getType().hasName("proto_tree *")
and vti_2302.getType().hasName("proto_item *")
and vtvb_2296.getType().hasName("tvbuff_t *")
and vmac_len_2310.getType().hasName("guint")
and vtvb_len_2311.getType().hasName("guint")
and vcalculated_crc_2313.getType().hasName("guint32")
and vproto_mac_mgmt_msg_dlmap_decoder.getType().hasName("gint")
and vhf_mac_header_compress_dlmap_crc.getType().hasName("gint")
and vhf_mac_header_compress_dlmap_crc_status.getType().hasName("gint")
and vei_mac_header_compress_dlmap_crc.getType().hasName("expert_field")
and vpinfo_2296.getParentScope+() = func
and vbase_tree_2296.getParentScope+() = func
and vti_2302.getParentScope+() = func
and vtvb_2296.getParentScope+() = func
and vmac_len_2310.getParentScope+() = func
and vtvb_len_2311.getParentScope+() = func
and vcalculated_crc_2313.getParentScope+() = func
and not vproto_mac_mgmt_msg_dlmap_decoder.getParentScope+() = func
and not vhf_mac_header_compress_dlmap_crc.getParentScope+() = func
and not vhf_mac_header_compress_dlmap_crc_status.getParentScope+() = func
and not vei_mac_header_compress_dlmap_crc.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
