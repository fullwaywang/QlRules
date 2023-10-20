/**
 * @name wireshark-0b473c01ab38e3b7debeeb4df82423fe53d0ff54-dissect_wlan_radio_phdr
 * @id cpp/wireshark/0b473c01ab38e3b7debeeb4df82423fe53d0ff54/dissect-wlan-radio-phdr
 * @description wireshark-0b473c01ab38e3b7debeeb4df82423fe53d0ff54-epan/dissectors/packet-ieee80211-radio.c-dissect_wlan_radio_phdr CVE-2021-39928
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwlan_radio_info_732, BlockStmt target_11, ExprStmt target_12, EqualityOperation target_13) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_0.getParent().(IfStmt).getThen()=target_11
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwlan_radio_info_732, BlockStmt target_14, ExprStmt target_15, EqualityOperation target_16) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_1.getParent().(IfStmt).getThen()=target_14
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vwlan_radio_info_732, BlockStmt target_17, AddExpr target_18, IfStmt target_19) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_2.getParent().(IfStmt).getThen()=target_17
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vwlan_radio_info_732, VariableAccess target_20, ExprStmt target_21, IfStmt target_5) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_3.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_3.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation())
		and target_3.getCondition().(VariableAccess).getLocation().isBefore(target_5.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vwlan_radio_info_732, BlockStmt target_11, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="aggregate"
		and target_4.getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_4.getParent().(IfStmt).getThen()=target_11
}

predicate func_5(Variable vp_item_722, Variable vwlan_radio_info_732, Parameter vtvb_712, Variable vitem_1428, Variable vd_tree_1429, Variable vagg_tree_1448, Variable vhf_wlan_radio_aggregate, Variable vett_wlan_radio_aggregate, Variable vaitem_1455, VariableAccess target_20, IfStmt target_5) {
		target_5.getCondition().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_5.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_item_722
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_none_format")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_tree_1429
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_wlan_radio_aggregate
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_712
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="This MPDU is part of an A-MPDU"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vagg_tree_1448
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_item_add_subtree")
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem_1428
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vett_wlan_radio_aggregate
		and target_5.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
		and target_5.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_item_722
		and target_5.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="duration"
		and target_5.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_5.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_5.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
		and target_5.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vaitem_1455
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

predicate func_6(Variable vp_item_722, Variable vwlan_radio_info_732, Parameter vtvb_712, Variable vd_tree_1429, Variable vhf_wlan_radio_ifs, VariableAccess target_20, IfStmt target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="ifs"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_item_722
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_int64")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_tree_1429
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_wlan_radio_ifs
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_712
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="ifs"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_item_722
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

predicate func_7(Variable vp_item_722, Variable vwlan_radio_info_732, Parameter vtvb_712, Variable vd_tree_1429, Variable vhf_wlan_radio_start_tsf, VariableAccess target_20, IfStmt target_7) {
		target_7.getCondition().(PointerFieldAccess).getTarget().getName()="start_tsf"
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_item_722
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_uint64")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_tree_1429
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_wlan_radio_start_tsf
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_712
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="start_tsf"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_item_722
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

predicate func_8(Variable vp_item_722, Variable vwlan_radio_info_732, Parameter vtvb_712, Variable vd_tree_1429, Variable vhf_wlan_radio_end_tsf, VariableAccess target_20, IfStmt target_8) {
		target_8.getCondition().(PointerFieldAccess).getTarget().getName()="end_tsf"
		and target_8.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_item_722
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_uint64")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_tree_1429
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_wlan_radio_end_tsf
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_712
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="end_tsf"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_item_722
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

predicate func_9(Variable vwlan_radio_info_732, BlockStmt target_14, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="aggregate"
		and target_9.getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_9.getParent().(IfStmt).getThen()=target_14
}

predicate func_10(Variable vwlan_radio_info_732, BlockStmt target_17, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="aggregate"
		and target_10.getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_10.getParent().(IfStmt).getThen()=target_17
}

predicate func_11(Variable vwlan_radio_info_732, BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="phy"
		and target_11.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_11.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_11.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="phy_info"
		and target_11.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_11.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
}

predicate func_12(Variable vwlan_radio_info_732, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("p_get_proto_data")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_13(Variable vwlan_radio_info_732, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vwlan_radio_info_732, BlockStmt target_14) {
		target_14.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_14.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_14.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calculate_11n_duration")
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_14.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
}

predicate func_15(Variable vwlan_radio_info_732, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="phy_info"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
}

predicate func_16(Variable vwlan_radio_info_732, EqualityOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_16.getAnOperand().(Literal).getValue()="0"
}

predicate func_17(Variable vwlan_radio_info_732, BlockStmt target_17) {
		target_17.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_17.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_17.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_17.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_17.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calculate_11ac_duration")
		and target_17.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_17.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
}

predicate func_18(Variable vwlan_radio_info_732, AddExpr target_18) {
		target_18.getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
}

predicate func_19(Variable vwlan_radio_info_732, IfStmt target_19) {
		target_19.getCondition().(PointerFieldAccess).getTarget().getName()="aggregate"
		and target_19.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_19.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_19.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_19.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calculate_11ac_duration")
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="prior_aggregate_data"
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_19.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("calculate_11ac_duration")
}

predicate func_20(Variable vhave_duration_728, VariableAccess target_20) {
		target_20.getTarget()=vhave_duration_728
}

predicate func_21(Variable vwlan_radio_info_732, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rssi"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwlan_radio_info_732
		and target_21.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="signal_dbm"
}

from Function func, Variable vp_item_722, Variable vhave_duration_728, Variable vwlan_radio_info_732, Parameter vtvb_712, Variable vitem_1428, Variable vd_tree_1429, Variable vagg_tree_1448, Variable vhf_wlan_radio_aggregate, Variable vett_wlan_radio_aggregate, Variable vaitem_1455, Variable vhf_wlan_radio_ifs, Variable vhf_wlan_radio_start_tsf, Variable vhf_wlan_radio_end_tsf, PointerFieldAccess target_4, IfStmt target_5, IfStmt target_6, IfStmt target_7, IfStmt target_8, PointerFieldAccess target_9, PointerFieldAccess target_10, BlockStmt target_11, ExprStmt target_12, EqualityOperation target_13, BlockStmt target_14, ExprStmt target_15, EqualityOperation target_16, BlockStmt target_17, AddExpr target_18, IfStmt target_19, VariableAccess target_20, ExprStmt target_21
where
not func_0(vwlan_radio_info_732, target_11, target_12, target_13)
and not func_1(vwlan_radio_info_732, target_14, target_15, target_16)
and not func_2(vwlan_radio_info_732, target_17, target_18, target_19)
and not func_3(vwlan_radio_info_732, target_20, target_21, target_5)
and func_4(vwlan_radio_info_732, target_11, target_4)
and func_5(vp_item_722, vwlan_radio_info_732, vtvb_712, vitem_1428, vd_tree_1429, vagg_tree_1448, vhf_wlan_radio_aggregate, vett_wlan_radio_aggregate, vaitem_1455, target_20, target_5)
and func_6(vp_item_722, vwlan_radio_info_732, vtvb_712, vd_tree_1429, vhf_wlan_radio_ifs, target_20, target_6)
and func_7(vp_item_722, vwlan_radio_info_732, vtvb_712, vd_tree_1429, vhf_wlan_radio_start_tsf, target_20, target_7)
and func_8(vp_item_722, vwlan_radio_info_732, vtvb_712, vd_tree_1429, vhf_wlan_radio_end_tsf, target_20, target_8)
and func_9(vwlan_radio_info_732, target_14, target_9)
and func_10(vwlan_radio_info_732, target_17, target_10)
and func_11(vwlan_radio_info_732, target_11)
and func_12(vwlan_radio_info_732, target_12)
and func_13(vwlan_radio_info_732, target_13)
and func_14(vwlan_radio_info_732, target_14)
and func_15(vwlan_radio_info_732, target_15)
and func_16(vwlan_radio_info_732, target_16)
and func_17(vwlan_radio_info_732, target_17)
and func_18(vwlan_radio_info_732, target_18)
and func_19(vwlan_radio_info_732, target_19)
and func_20(vhave_duration_728, target_20)
and func_21(vwlan_radio_info_732, target_21)
and vp_item_722.getType().hasName("proto_item *")
and vhave_duration_728.getType().hasName("gboolean")
and vwlan_radio_info_732.getType().hasName("wlan_radio *")
and vtvb_712.getType().hasName("tvbuff_t *")
and vitem_1428.getType().hasName("proto_item *")
and vd_tree_1429.getType().hasName("proto_tree *")
and vagg_tree_1448.getType().hasName("proto_tree *")
and vhf_wlan_radio_aggregate.getType().hasName("int")
and vett_wlan_radio_aggregate.getType().hasName("gint")
and vaitem_1455.getType().hasName("proto_item *")
and vhf_wlan_radio_ifs.getType().hasName("int")
and vhf_wlan_radio_start_tsf.getType().hasName("int")
and vhf_wlan_radio_end_tsf.getType().hasName("int")
and vp_item_722.getParentScope+() = func
and vhave_duration_728.getParentScope+() = func
and vwlan_radio_info_732.getParentScope+() = func
and vtvb_712.getParentScope+() = func
and vitem_1428.getParentScope+() = func
and vd_tree_1429.getParentScope+() = func
and vagg_tree_1448.getParentScope+() = func
and not vhf_wlan_radio_aggregate.getParentScope+() = func
and not vett_wlan_radio_aggregate.getParentScope+() = func
and vaitem_1455.getParentScope+() = func
and not vhf_wlan_radio_ifs.getParentScope+() = func
and not vhf_wlan_radio_start_tsf.getParentScope+() = func
and not vhf_wlan_radio_end_tsf.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
