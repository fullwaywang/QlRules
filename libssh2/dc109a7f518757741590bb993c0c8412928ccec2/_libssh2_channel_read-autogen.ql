/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_channel_read
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-channel-read
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-_libssh2_channel_read CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vreadpkt_1830, BlockStmt target_15, PointerArithmeticOperation target_16) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_2.getGreaterOperand().(Literal).getValue()="5"
		and target_2.getParent().(IfStmt).getThen()=target_15
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vread_packet_1783, Variable vread_next_1784, LogicalOrExpr target_17, ExprStmt target_10, ExprStmt target_14) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_packet_1783
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vread_next_1784
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_4(LogicalOrExpr target_17, Function func) {
	exists(ContinueStmt target_4 |
		target_4.toString() = "continue;"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vchannel_1775, Parameter vstream_id_1775, Parameter vbuf_1776, Parameter vbuflen_1776, Variable vbytes_read_1780, Variable vbytes_want_1781, Variable vunlink_packet_1782, Variable vreadpkt_1830, LogicalOrExpr target_17, LogicalOrExpr target_18, LogicalAndExpr target_19, NotExpr target_20) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="extended_data_ignore_mode"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuflen_1776
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_read_1780
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vunlink_packet_1782
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vunlink_packet_1782
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getThen().(BlockStmt).getStmt(3).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(3).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_1776
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbytes_read_1780
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_5.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_5.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_5.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vbytes_read_1780
		and target_5.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vbytes_want_1781
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getCondition().(VariableAccess).getTarget()=vunlink_packet_1782
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_list_remove")
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_5.getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vreadpkt_1830
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_20.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vreadpkt_1830, LogicalOrExpr target_17) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand() instanceof LogicalAndExpr
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9")
}

*/
/*predicate func_7(LogicalOrExpr target_17, Function func) {
	exists(DoStmt target_7 |
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_7.getEnclosingFunction() = func)
}

*/
predicate func_8(Function func) {
	exists(LabelStmt target_8 |
		target_8.toString() = "label ...:"
		and target_8.getEnclosingFunction() = func)
}

predicate func_10(Variable vread_next_1784, Variable vreadpkt_1830, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_next_1784
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_list_next")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
}

predicate func_11(Parameter vchannel_1775, Variable vreadpkt_1830, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_12(Parameter vchannel_1775, Parameter vstream_id_1775, Variable vreadpkt_1830, LogicalAndExpr target_12) {
		target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
}

predicate func_13(LogicalOrExpr target_17, Function func, DoStmt target_13) {
		target_13.getCondition().(Literal).getValue()="0"
		and target_13.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Variable vread_packet_1783, Variable vread_next_1784, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_packet_1783
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vread_next_1784
}

predicate func_15(Parameter vbuflen_1776, Variable vbytes_read_1780, Variable vbytes_want_1781, Variable vunlink_packet_1782, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_want_1781
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuflen_1776
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_read_1780
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vunlink_packet_1782
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_16(Variable vreadpkt_1830, PointerArithmeticOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreadpkt_1830
		and target_16.getAnOperand().(Literal).getValue()="1"
}

predicate func_17(Parameter vchannel_1775, Parameter vstream_id_1775, LogicalOrExpr target_17) {
		target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1775
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read_local_id"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="extended_data_ignore_mode"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_17.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_18(Parameter vchannel_1775, LogicalOrExpr target_18) {
		target_18.getAnOperand().(ValueFieldAccess).getTarget().getName()="eof"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
		and target_18.getAnOperand().(ValueFieldAccess).getTarget().getName()="close"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1775
}

predicate func_19(Parameter vbuflen_1776, Variable vbytes_read_1780, Variable vread_packet_1783, LogicalAndExpr target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vread_packet_1783
		and target_19.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_read_1780
		and target_19.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuflen_1776
}

predicate func_20(Variable vbytes_read_1780, NotExpr target_20) {
		target_20.getOperand().(VariableAccess).getTarget()=vbytes_read_1780
}

from Function func, Parameter vchannel_1775, Parameter vstream_id_1775, Parameter vbuf_1776, Parameter vbuflen_1776, Variable vbytes_read_1780, Variable vbytes_want_1781, Variable vunlink_packet_1782, Variable vread_packet_1783, Variable vread_next_1784, Variable vreadpkt_1830, ExprStmt target_10, ExprStmt target_11, LogicalAndExpr target_12, DoStmt target_13, ExprStmt target_14, BlockStmt target_15, PointerArithmeticOperation target_16, LogicalOrExpr target_17, LogicalOrExpr target_18, LogicalAndExpr target_19, NotExpr target_20
where
not func_2(vreadpkt_1830, target_15, target_16)
and not func_3(vread_packet_1783, vread_next_1784, target_17, target_10, target_14)
and not func_4(target_17, func)
and not func_5(vchannel_1775, vstream_id_1775, vbuf_1776, vbuflen_1776, vbytes_read_1780, vbytes_want_1781, vunlink_packet_1782, vreadpkt_1830, target_17, target_18, target_19, target_20)
and not func_8(func)
and func_10(vread_next_1784, vreadpkt_1830, target_10)
and func_11(vchannel_1775, vreadpkt_1830, target_11)
and func_12(vchannel_1775, vstream_id_1775, vreadpkt_1830, target_12)
and func_13(target_17, func, target_13)
and func_14(vread_packet_1783, vread_next_1784, target_14)
and func_15(vbuflen_1776, vbytes_read_1780, vbytes_want_1781, vunlink_packet_1782, target_15)
and func_16(vreadpkt_1830, target_16)
and func_17(vchannel_1775, vstream_id_1775, target_17)
and func_18(vchannel_1775, target_18)
and func_19(vbuflen_1776, vbytes_read_1780, vread_packet_1783, target_19)
and func_20(vbytes_read_1780, target_20)
and vchannel_1775.getType().hasName("LIBSSH2_CHANNEL *")
and vstream_id_1775.getType().hasName("int")
and vbuf_1776.getType().hasName("char *")
and vbuflen_1776.getType().hasName("size_t")
and vbytes_read_1780.getType().hasName("int")
and vbytes_want_1781.getType().hasName("int")
and vunlink_packet_1782.getType().hasName("int")
and vread_packet_1783.getType().hasName("LIBSSH2_PACKET *")
and vread_next_1784.getType().hasName("LIBSSH2_PACKET *")
and vreadpkt_1830.getType().hasName("LIBSSH2_PACKET *")
and vchannel_1775.getParentScope+() = func
and vstream_id_1775.getParentScope+() = func
and vbuf_1776.getParentScope+() = func
and vbuflen_1776.getParentScope+() = func
and vbytes_read_1780.getParentScope+() = func
and vbytes_want_1781.getParentScope+() = func
and vunlink_packet_1782.getParentScope+() = func
and vread_packet_1783.getParentScope+() = func
and vread_next_1784.getParentScope+() = func
and vreadpkt_1830.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
