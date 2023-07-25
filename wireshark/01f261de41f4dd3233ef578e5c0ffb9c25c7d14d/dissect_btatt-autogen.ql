/**
 * @name wireshark-01f261de41f4dd3233ef578e5c0ffb9c25c7d14d-dissect_btatt
 * @id cpp/wireshark/01f261de41f4dd3233ef578e5c0ffb9c25c7d14d/dissect-btatt
 * @description wireshark-01f261de41f4dd3233ef578e5c0ffb9c25c7d14d-epan/dissectors/packet-btatt.c-dissect_btatt CVE-2020-7045
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_14, ExprStmt target_15, ValueFieldAccess target_16, ValueFieldAccess target_17) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_0.getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_0.getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
		and target_0.getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_18, ExprStmt target_19, ValueFieldAccess target_20, ValueFieldAccess target_21) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_18
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_21.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_22, LogicalAndExpr target_23, ValueFieldAccess target_24) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen()=target_22
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_25, ExprStmt target_26, LogicalAndExpr target_27, IfStmt target_28) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen()=target_25
		and target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_28.getCondition().(VariableAccess).getLocation()))
}

predicate func_4(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_14, LogicalAndExpr target_29, LogicalAndExpr target_30) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getAnOperand() instanceof RelationalOperation
		and target_4.getParent().(IfStmt).getThen()=target_14
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_30.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_31, ExprStmt target_15, ValueFieldAccess target_32, IfStmt target_33) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen()=target_31
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_32.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_33.getCondition().(VariableAccess).getLocation()))
}

predicate func_6(Variable vopcode_10730, Variable vrequest_data_10734, BlockStmt target_34, ValueFieldAccess target_35, IfStmt target_36) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getParent().(IfStmt).getThen()=target_34
		and target_35.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_36.getCondition().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vtvb_10723, Variable vrequest_data_10734, Variable vmtu_10737, BlockStmt target_14, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(FunctionCall).getTarget().hasName("tvb_captured_length")
		and target_7.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_10723
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vmtu_10737
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_8(Variable vrequest_data_10734, BlockStmt target_37, VariableAccess target_8) {
		target_8.getTarget()=vrequest_data_10734
		and target_8.getParent().(IfStmt).getThen()=target_37
}

predicate func_9(Variable vrequest_data_10734, BlockStmt target_18, VariableAccess target_9) {
		target_9.getTarget()=vrequest_data_10734
		and target_9.getParent().(IfStmt).getThen()=target_18
}

predicate func_10(Variable vrequest_data_10734, BlockStmt target_22, VariableAccess target_10) {
		target_10.getTarget()=vrequest_data_10734
		and target_10.getParent().(IfStmt).getThen()=target_22
}

predicate func_11(Variable vrequest_data_10734, BlockStmt target_25, VariableAccess target_11) {
		target_11.getTarget()=vrequest_data_10734
		and target_11.getParent().(IfStmt).getThen()=target_25
}

predicate func_12(Variable vrequest_data_10734, BlockStmt target_31, VariableAccess target_12) {
		target_12.getTarget()=vrequest_data_10734
		and target_12.getParent().(IfStmt).getThen()=target_31
}

predicate func_13(Variable vrequest_data_10734, BlockStmt target_34, VariableAccess target_13) {
		target_13.getTarget()=vrequest_data_10734
		and target_13.getParent().(IfStmt).getThen()=target_34
}

predicate func_14(Parameter vtvb_10723, BlockStmt target_14) {
		target_14.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_14.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_10723
		and target_14.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_14.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_14.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_value")
		and target_14.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="handle"
		and target_14.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_14.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
}

predicate func_15(Variable vopcode_10730, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("save_request")
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vopcode_10730
}

predicate func_16(Variable vrequest_data_10734, ValueFieldAccess target_16) {
		target_16.getTarget().getName()="read_write"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_17(Variable vrequest_data_10734, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="read_write"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_18(Parameter vtvb_10723, Variable vrequest_data_10734, BlockStmt target_18) {
		target_18.getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_18.getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="number_of_handles"
		and target_18.getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_multiple"
		and target_18.getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_18.getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_18.getStmt(1).(ForStmt).getUpdate().(AssignAddExpr).getRValue().(Literal).getValue()="1"
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="handle"
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dissect_attribute_value")
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_18.getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(FunctionCall).getTarget().hasName("tvb_captured_length_remaining")
}

predicate func_19(Variable vopcode_10730, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("save_request")
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vopcode_10730
}

predicate func_20(Variable vrequest_data_10734, ValueFieldAccess target_20) {
		target_20.getTarget().getName()="read_write"
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_21(Variable vrequest_data_10734, ValueFieldAccess target_21) {
		target_21.getTarget().getName()="read_by_type"
		and target_21.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_21.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_22(Parameter vtvb_10723, BlockStmt target_22) {
		target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_uint")
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_10723
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="bt_uuid"
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="uuid"
		and target_22.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_by_type"
}

predicate func_23(Variable vopcode_10730, LogicalAndExpr target_23) {
		target_23.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="visited"
		and target_23.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fd"
		and target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="18"
		and target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="29"
}

predicate func_24(Variable vrequest_data_10734, ValueFieldAccess target_24) {
		target_24.getTarget().getName()="read_write"
		and target_24.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_25(Parameter vtvb_10723, Variable vrequest_data_10734, BlockStmt target_25) {
		target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="handle"
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_26(Variable vopcode_10730, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("save_request")
		and target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vopcode_10730
}

predicate func_27(Variable vopcode_10730, LogicalAndExpr target_27) {
		target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="visited"
		and target_27.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fd"
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_27.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="22"
}

predicate func_28(Parameter vtvb_10723, Variable vrequest_data_10734, IfStmt target_28) {
		target_28.getCondition().(VariableAccess).getTarget()=vrequest_data_10734
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="handle"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
}

predicate func_29(Variable vopcode_10730, Variable vrequest_data_10734, LogicalAndExpr target_29) {
		target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="visited"
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fd"
		and target_29.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vopcode_10730
		and target_29.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="22"
}

predicate func_30(Variable vrequest_data_10734, LogicalAndExpr target_30) {
		target_30.getAnOperand().(VariableAccess).getTarget()=vrequest_data_10734
		and target_30.getAnOperand() instanceof RelationalOperation
}

predicate func_31(Parameter vtvb_10723, Variable vrequest_data_10734, BlockStmt target_31) {
		target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="handle"
		and target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_31.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_32(Variable vrequest_data_10734, ValueFieldAccess target_32) {
		target_32.getTarget().getName()="read_write"
		and target_32.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_32.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_33(Parameter vtvb_10723, Variable vrequest_data_10734, IfStmt target_33) {
		target_33.getCondition().(VariableAccess).getTarget()=vrequest_data_10734
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="handle"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_33.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
}

predicate func_34(Parameter vtvb_10723, Variable vrequest_data_10734, BlockStmt target_34) {
		target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="request_in_frame"
		and target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="request_in_frame"
		and target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_34.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num"
		and target_34.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_uint")
		and target_34.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_10723
		and target_34.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_34.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_34.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="request_in_frame"
}

predicate func_35(Variable vrequest_data_10734, ValueFieldAccess target_35) {
		target_35.getTarget().getName()="read_write"
		and target_35.getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_35.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

predicate func_36(Variable vrequest_data_10734, IfStmt target_36) {
		target_36.getCondition().(VariableAccess).getTarget()=vrequest_data_10734
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="request_in_frame"
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="request_in_frame"
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num"
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_uint")
		and target_36.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_item_set_generated")
}

predicate func_37(Parameter vtvb_10723, Variable vrequest_data_10734, BlockStmt target_37) {
		target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dissect_handle")
		and target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_10723
		and target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="handle"
		and target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="read_write"
		and target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parameters"
		and target_37.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrequest_data_10734
}

from Function func, Parameter vtvb_10723, Variable vopcode_10730, Variable vrequest_data_10734, Variable vmtu_10737, RelationalOperation target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, BlockStmt target_14, ExprStmt target_15, ValueFieldAccess target_16, ValueFieldAccess target_17, BlockStmt target_18, ExprStmt target_19, ValueFieldAccess target_20, ValueFieldAccess target_21, BlockStmt target_22, LogicalAndExpr target_23, ValueFieldAccess target_24, BlockStmt target_25, ExprStmt target_26, LogicalAndExpr target_27, IfStmt target_28, LogicalAndExpr target_29, LogicalAndExpr target_30, BlockStmt target_31, ValueFieldAccess target_32, IfStmt target_33, BlockStmt target_34, ValueFieldAccess target_35, IfStmt target_36, BlockStmt target_37
where
not func_0(vopcode_10730, vrequest_data_10734, target_14, target_15, target_16, target_17)
and not func_1(vopcode_10730, vrequest_data_10734, target_18, target_19, target_20, target_21)
and not func_2(vopcode_10730, vrequest_data_10734, target_22, target_23, target_24)
and not func_3(vopcode_10730, vrequest_data_10734, target_25, target_26, target_27, target_28)
and not func_4(vopcode_10730, vrequest_data_10734, target_14, target_29, target_30)
and not func_5(vopcode_10730, vrequest_data_10734, target_31, target_15, target_32, target_33)
and not func_6(vopcode_10730, vrequest_data_10734, target_34, target_35, target_36)
and func_7(vtvb_10723, vrequest_data_10734, vmtu_10737, target_14, target_7)
and func_8(vrequest_data_10734, target_37, target_8)
and func_9(vrequest_data_10734, target_18, target_9)
and func_10(vrequest_data_10734, target_22, target_10)
and func_11(vrequest_data_10734, target_25, target_11)
and func_12(vrequest_data_10734, target_31, target_12)
and func_13(vrequest_data_10734, target_34, target_13)
and func_14(vtvb_10723, target_14)
and func_15(vopcode_10730, target_15)
and func_16(vrequest_data_10734, target_16)
and func_17(vrequest_data_10734, target_17)
and func_18(vtvb_10723, vrequest_data_10734, target_18)
and func_19(vopcode_10730, target_19)
and func_20(vrequest_data_10734, target_20)
and func_21(vrequest_data_10734, target_21)
and func_22(vtvb_10723, target_22)
and func_23(vopcode_10730, target_23)
and func_24(vrequest_data_10734, target_24)
and func_25(vtvb_10723, vrequest_data_10734, target_25)
and func_26(vopcode_10730, target_26)
and func_27(vopcode_10730, target_27)
and func_28(vtvb_10723, vrequest_data_10734, target_28)
and func_29(vopcode_10730, vrequest_data_10734, target_29)
and func_30(vrequest_data_10734, target_30)
and func_31(vtvb_10723, vrequest_data_10734, target_31)
and func_32(vrequest_data_10734, target_32)
and func_33(vtvb_10723, vrequest_data_10734, target_33)
and func_34(vtvb_10723, vrequest_data_10734, target_34)
and func_35(vrequest_data_10734, target_35)
and func_36(vrequest_data_10734, target_36)
and func_37(vtvb_10723, vrequest_data_10734, target_37)
and vtvb_10723.getType().hasName("tvbuff_t *")
and vopcode_10730.getType().hasName("guint8")
and vrequest_data_10734.getType().hasName("request_data_t *")
and vmtu_10737.getType().hasName("guint")
and vtvb_10723.getParentScope+() = func
and vopcode_10730.getParentScope+() = func
and vrequest_data_10734.getParentScope+() = func
and vmtu_10737.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
