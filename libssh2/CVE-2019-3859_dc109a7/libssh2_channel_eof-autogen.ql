/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-libssh2_channel_eof
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/libssh2-channel-eof
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-libssh2_channel_eof CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpacket_2222, VariableAccess target_0) {
		target_0.getTarget()=vpacket_2222
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_list_next")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
}

predicate func_1(Variable vpacket_2222, BlockStmt target_10, WhileStmt target_11) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_1.getGreaterOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_10
		and target_11.getCondition().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpacket_2222, LogicalAndExpr target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_2222
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12)
}

predicate func_3(LogicalAndExpr target_12, Function func) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(LogicalAndExpr target_12, Function func) {
	exists(ContinueStmt target_4 |
		target_4.toString() = "continue;"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vpacket_2222, PointerArithmeticOperation target_13) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vpacket_2222, BlockStmt target_10, LogicalAndExpr target_12, PointerArithmeticOperation target_13) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_6.getAnOperand() instanceof EqualityOperation
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_6.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_7(Variable vpacket_2222, AddressOfExpr target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_2222
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("LIBSSH2_PACKET *")
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_8(Function func) {
	exists(LabelStmt target_8 |
		target_8.toString() = "label ...:"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vchannel_2219, Variable vpacket_2222, BlockStmt target_10, EqualityOperation target_9) {
		target_9.getAnOperand().(ValueFieldAccess).getTarget().getName()="id"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchannel_2219
		and target_9.getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_10
}

predicate func_10(BlockStmt target_10) {
		target_10.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_11(Variable vpacket_2222, WhileStmt target_11) {
		target_11.getCondition().(VariableAccess).getTarget()=vpacket_2222
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_11.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpacket_2222
		and target_11.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_list_next")
		and target_11.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
}

predicate func_12(Variable vpacket_2222, LogicalAndExpr target_12) {
		target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="94"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="95"
		and target_12.getAnOperand() instanceof EqualityOperation
}

predicate func_13(Variable vpacket_2222, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
		and target_13.getAnOperand().(Literal).getValue()="1"
}

predicate func_14(Variable vpacket_2222, AddressOfExpr target_14) {
		target_14.getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpacket_2222
}

from Function func, Parameter vchannel_2219, Variable vpacket_2222, VariableAccess target_0, EqualityOperation target_9, BlockStmt target_10, WhileStmt target_11, LogicalAndExpr target_12, PointerArithmeticOperation target_13, AddressOfExpr target_14
where
func_0(vpacket_2222, target_0)
and not func_1(vpacket_2222, target_10, target_11)
and not func_2(vpacket_2222, target_12)
and not func_3(target_12, func)
and not func_4(target_12, func)
and not func_5(vpacket_2222, target_13)
and not func_7(vpacket_2222, target_14)
and not func_8(func)
and func_9(vchannel_2219, vpacket_2222, target_10, target_9)
and func_10(target_10)
and func_11(vpacket_2222, target_11)
and func_12(vpacket_2222, target_12)
and func_13(vpacket_2222, target_13)
and func_14(vpacket_2222, target_14)
and vchannel_2219.getType().hasName("LIBSSH2_CHANNEL *")
and vpacket_2222.getType().hasName("LIBSSH2_PACKET *")
and vchannel_2219.getParentScope+() = func
and vpacket_2222.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
