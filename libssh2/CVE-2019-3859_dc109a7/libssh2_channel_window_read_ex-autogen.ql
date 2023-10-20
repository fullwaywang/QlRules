/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-libssh2_channel_window_read_ex
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/libssh2-channel-window-read-ex
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-libssh2_channel_window_read_ex CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpacket_2597, VariableAccess target_0) {
		target_0.getTarget()=vpacket_2597
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_list_next")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
}

predicate func_1(Variable vpacket_2597, BlockStmt target_13, ArrayExpr target_10) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_1.getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_13
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpacket_2597, LogicalAndExpr target_14) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_2597
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14)
}

predicate func_3(LogicalAndExpr target_14, Function func) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(LogicalAndExpr target_14, Function func) {
	exists(ContinueStmt target_4 |
		target_4.toString() = "continue;"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vpacket_type_2601) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_type_2601
		and target_5.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr)
}

predicate func_6(Variable vbytes_queued_2596, Variable vpacket_2597, Variable vpacket_type_2601, ExprStmt target_15) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vbytes_queued_2596
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_7(Variable vpacket_2597, Variable vpacket_type_2601, BlockStmt target_13, PointerArithmeticOperation target_16) {
	exists(LogicalAndExpr target_7 |
		target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_7.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_7.getAnOperand() instanceof EqualityOperation
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_7.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_8(Variable vpacket_2597, WhileStmt target_17, ArrayExpr target_10) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_2597
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_17.getCondition().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Function func) {
	exists(LabelStmt target_9 |
		target_9.toString() = "label ...:"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vpacket_2597, ArrayExpr target_10) {
		target_10.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_10.getArrayOffset().(Literal).getValue()="0"
}

predicate func_11(Variable vpacket_2597, Variable vpacket_type_2601, Parameter vchannel_2584, BlockStmt target_13, EqualityOperation target_11) {
		target_11.getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_11.getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_2584
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_11.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
}

predicate func_12(Function func, Initializer target_12) {
		target_12.getExpr() instanceof ArrayExpr
		and target_12.getExpr().getEnclosingFunction() = func
}

predicate func_13(Variable vbytes_queued_2596, Variable vpacket_2597, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vbytes_queued_2596
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="data_head"
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
}

predicate func_14(Variable vpacket_type_2601, LogicalAndExpr target_14) {
		target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_14.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_14.getAnOperand() instanceof EqualityOperation
}

predicate func_15(Variable vbytes_queued_2596, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbytes_queued_2596
}

predicate func_16(Variable vpacket_2597, PointerArithmeticOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2597
		and target_16.getAnOperand().(Literal).getValue()="1"
}

predicate func_17(Variable vbytes_queued_2596, Variable vpacket_2597, Variable vpacket_type_2601, WhileStmt target_17) {
		target_17.getCondition().(VariableAccess).getTarget()=vpacket_2597
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpacket_type_2601
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vbytes_queued_2596
}

from Function func, Variable vbytes_queued_2596, Variable vpacket_2597, Variable vpacket_type_2601, Parameter vchannel_2584, VariableAccess target_0, ArrayExpr target_10, EqualityOperation target_11, Initializer target_12, BlockStmt target_13, LogicalAndExpr target_14, ExprStmt target_15, PointerArithmeticOperation target_16, WhileStmt target_17
where
func_0(vpacket_2597, target_0)
and not func_1(vpacket_2597, target_13, target_10)
and not func_2(vpacket_2597, target_14)
and not func_3(target_14, func)
and not func_4(target_14, func)
and not func_5(vpacket_type_2601)
and not func_6(vbytes_queued_2596, vpacket_2597, vpacket_type_2601, target_15)
and not func_8(vpacket_2597, target_17, target_10)
and not func_9(func)
and func_10(vpacket_2597, target_10)
and func_11(vpacket_2597, vpacket_type_2601, vchannel_2584, target_13, target_11)
and func_12(func, target_12)
and func_13(vbytes_queued_2596, vpacket_2597, target_13)
and func_14(vpacket_type_2601, target_14)
and func_15(vbytes_queued_2596, target_15)
and func_16(vpacket_2597, target_16)
and func_17(vbytes_queued_2596, vpacket_2597, vpacket_type_2601, target_17)
and vbytes_queued_2596.getType().hasName("size_t")
and vpacket_2597.getType().hasName("LIBSSH2_PACKET *")
and vpacket_type_2601.getType().hasName("unsigned char")
and vchannel_2584.getType().hasName("LIBSSH2_CHANNEL *")
and vbytes_queued_2596.getParentScope+() = func
and vpacket_2597.getParentScope+() = func
and vpacket_type_2601.getParentScope+() = func
and vchannel_2584.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
