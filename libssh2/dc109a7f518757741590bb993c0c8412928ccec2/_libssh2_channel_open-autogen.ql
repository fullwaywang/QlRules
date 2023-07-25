/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-_libssh2_channel_open
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/-libssh2-channel-open
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/channel.c-_libssh2_channel_open CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsession_129, BlockStmt target_16, ExprStmt target_17, EqualityOperation target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(PointerFieldAccess).getTarget().getName()="open_data_len"
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_0.getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_16
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsession_129, EqualityOperation target_4, PointerFieldAccess target_18) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_129
		and target_1.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_4, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="channel_error"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vsession_129, EqualityOperation target_19, ReturnStmt target_15, EqualityOperation target_20) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof EqualityOperation
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="open_data_len"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="17"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_129
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected packet size"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="channel_error"
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(5) instanceof DoStmt
		and target_3.getThen().(BlockStmt).getStmt(6) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(9) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(10) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(11) instanceof ReturnStmt
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_15.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vsession_129, BlockStmt target_16, EqualityOperation target_4) {
		target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_4.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getAnOperand().(Literal).getValue()="91"
		and target_4.getParent().(IfStmt).getThen()=target_16
}

predicate func_5(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="id"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="remote"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="window_size"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_7(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="window_size_initial"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="9"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_8(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="packet_size"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="local"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="13"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_9(EqualityOperation target_4, Function func, DoStmt target_9) {
		target_9.getCondition().(Literal).getValue()="0"
		and target_9.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_10) {
		target_10.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_10.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_10.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="open_packet"
		and target_10.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_10.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_10.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_11(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="open_packet"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_12(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_12) {
		target_12.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_12.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="open_data"
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_12.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_13(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_14(Parameter vsession_129, EqualityOperation target_4, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="open_state"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_15(Parameter vsession_129, EqualityOperation target_4, ReturnStmt target_15) {
		target_15.getExpr().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_15.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0) instanceof ExprStmt
		and target_16.getStmt(1) instanceof ExprStmt
		and target_16.getStmt(2) instanceof ExprStmt
		and target_16.getStmt(3) instanceof ExprStmt
		and target_16.getStmt(4) instanceof DoStmt
}

predicate func_17(Parameter vsession_129, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_129
		and target_17.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_17.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Would block"
}

predicate func_18(Parameter vsession_129, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="remote"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="open_channel"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
}

predicate func_19(Parameter vsession_129, EqualityOperation target_19) {
		target_19.getAnOperand().(PointerFieldAccess).getTarget().getName()="open_state"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
}

predicate func_20(Parameter vsession_129, EqualityOperation target_20) {
		target_20.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="open_data"
		and target_20.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_129
		and target_20.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getAnOperand().(Literal).getValue()="92"
}

from Function func, Parameter vsession_129, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, DoStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ReturnStmt target_15, BlockStmt target_16, ExprStmt target_17, PointerFieldAccess target_18, EqualityOperation target_19, EqualityOperation target_20
where
not func_0(vsession_129, target_16, target_17, target_4)
and not func_1(vsession_129, target_4, target_18)
and not func_2(target_4, func)
and not func_3(vsession_129, target_19, target_15, target_20)
and func_4(vsession_129, target_16, target_4)
and func_5(vsession_129, target_4, target_5)
and func_6(vsession_129, target_4, target_6)
and func_7(vsession_129, target_4, target_7)
and func_8(vsession_129, target_4, target_8)
and func_9(target_4, func, target_9)
and func_10(vsession_129, target_4, target_10)
and func_11(vsession_129, target_4, target_11)
and func_12(vsession_129, target_4, target_12)
and func_13(vsession_129, target_4, target_13)
and func_14(vsession_129, target_4, target_14)
and func_15(vsession_129, target_4, target_15)
and func_16(target_16)
and func_17(vsession_129, target_17)
and func_18(vsession_129, target_18)
and func_19(vsession_129, target_19)
and func_20(vsession_129, target_20)
and vsession_129.getType().hasName("LIBSSH2_SESSION *")
and vsession_129.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
