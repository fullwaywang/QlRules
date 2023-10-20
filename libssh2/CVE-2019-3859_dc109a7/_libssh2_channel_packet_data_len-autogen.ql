/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_channel_packet_data_len
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-channel-packet-data-len
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-_libssh2_channel_packet_data_len CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vread_packet_1963, VariableAccess target_0) {
		target_0.getTarget()=vread_packet_1963
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_list_next")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
}

predicate func_1(Variable vread_packet_1963, BlockStmt target_10, PointerArithmeticOperation target_11) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_1.getGreaterOperand().(Literal).getValue()="5"
		and target_1.getParent().(IfStmt).getThen()=target_10
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vread_packet_1963, LogicalOrExpr target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_packet_1963
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12)
}

predicate func_3(LogicalOrExpr target_12, Function func) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(LogicalOrExpr target_12, Function func) {
	exists(ContinueStmt target_4 |
		target_4.toString() = "continue;"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vstream_id_1960, Variable vread_packet_1963, Variable vread_local_id_1964, Parameter vchannel_1960, LogicalOrExpr target_12) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_local_id_1964
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_local_id_1964
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="extended_data_ignore_mode"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1960
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vread_packet_1963, LogicalOrExpr target_12) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand() instanceof LogicalAndExpr
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9")
}

*/
predicate func_7(Variable vread_packet_1963, AddressOfExpr target_13) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vread_packet_1963
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_8(Function func) {
	exists(LabelStmt target_8 |
		target_8.toString() = "label ...:"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vstream_id_1960, Variable vread_packet_1963, Variable vread_local_id_1964, Parameter vchannel_1960, LogicalAndExpr target_9) {
		target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1960
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_local_id_1964
}

predicate func_10(Variable vread_packet_1963, BlockStmt target_10) {
		target_10.getStmt(0).(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_10.getStmt(0).(ReturnStmt).getExpr().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_10.getStmt(0).(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_10.getStmt(0).(ReturnStmt).getExpr().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
}

predicate func_11(Variable vread_packet_1963, PointerArithmeticOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
		and target_11.getAnOperand().(Literal).getValue()="1"
}

predicate func_12(Parameter vstream_id_1960, Variable vread_local_id_1964, Parameter vchannel_1960, LogicalOrExpr target_12) {
		target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1960
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_local_id_1964
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vstream_id_1960
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1960
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_local_id_1964
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="extended_data_ignore_mode"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_1960
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_13(Variable vread_packet_1963, AddressOfExpr target_13) {
		target_13.getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vread_packet_1963
}

from Function func, Parameter vstream_id_1960, Variable vread_packet_1963, Variable vread_local_id_1964, Parameter vchannel_1960, VariableAccess target_0, LogicalAndExpr target_9, BlockStmt target_10, PointerArithmeticOperation target_11, LogicalOrExpr target_12, AddressOfExpr target_13
where
func_0(vread_packet_1963, target_0)
and not func_1(vread_packet_1963, target_10, target_11)
and not func_2(vread_packet_1963, target_12)
and not func_3(target_12, func)
and not func_4(target_12, func)
and not func_5(vstream_id_1960, vread_packet_1963, vread_local_id_1964, vchannel_1960, target_12)
and not func_7(vread_packet_1963, target_13)
and not func_8(func)
and func_9(vstream_id_1960, vread_packet_1963, vread_local_id_1964, vchannel_1960, target_9)
and func_10(vread_packet_1963, target_10)
and func_11(vread_packet_1963, target_11)
and func_12(vstream_id_1960, vread_local_id_1964, vchannel_1960, target_12)
and func_13(vread_packet_1963, target_13)
and vstream_id_1960.getType().hasName("int")
and vread_packet_1963.getType().hasName("LIBSSH2_PACKET *")
and vread_local_id_1964.getType().hasName("uint32_t")
and vchannel_1960.getType().hasName("LIBSSH2_CHANNEL *")
and vstream_id_1960.getParentScope+() = func
and vread_packet_1963.getParentScope+() = func
and vread_local_id_1964.getParentScope+() = func
and vchannel_1960.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
