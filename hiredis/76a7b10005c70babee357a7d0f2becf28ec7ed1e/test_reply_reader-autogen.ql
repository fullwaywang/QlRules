/**
 * @name hiredis-76a7b10005c70babee357a7d0f2becf28ec7ed1e-test_reply_reader
 * @id cpp/hiredis/76a7b10005c70babee357a7d0f2becf28ec7ed1e/test-reply-reader
 * @description hiredis-76a7b10005c70babee357a7d0f2becf28ec7ed1e-test.c-test_reply_reader CVE-2021-32765
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtests, PrefixIncrExpr target_12, PrefixIncrExpr target_13) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_0.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="#%02d "
		and target_0.getExpr().(FunctionCall).getArgument(1).(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vtests
		and target_12.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(PrefixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(1).(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_13.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_1.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Multi-bulk never overflows regardless of maxelements: "
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[100]")
		and target_2.getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="100"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="*%llu\r\n+asdf\r\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(106)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(106).getFollowingStmt()=target_2))
}

predicate func_3(Variable vreader_383, ExprStmt target_14, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="maxelements"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreader_383
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(108)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(108).getFollowingStmt()=target_3)
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vreader_383, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("redisReaderFeed")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char[100]")
		and target_4.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_4.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char[100]")
		and (func.getEntryPoint().(BlockStmt).getStmt(109)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(109).getFollowingStmt()=target_4))
}

predicate func_5(Variable vreader_383, Variable vret_385, Variable vfails, ExprStmt target_15, ExprStmt target_16, LogicalAndExpr target_17, ExprStmt target_18, ExprStmt target_19, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_385
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcasecmp")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="errstr"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreader_383
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Out of memory"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="[0;32mPASSED[0;0m\n"
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="[0;31mFAILED[0;0m\n"
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vfails
		and (func.getEntryPoint().(BlockStmt).getStmt(111)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(111).getFollowingStmt()=target_5)
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_18.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vreader_383, ExprStmt target_20, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreader_383
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("redisReaderCreate")
		and (func.getEntryPoint().(BlockStmt).getStmt(167)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(167).getFollowingStmt()=target_7)
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_8(Variable vreader_383, Variable vreply_384, Variable vret_385, ExprStmt target_21, ExprStmt target_22, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_385
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("redisReaderGetReply")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vreply_384
		and (func.getEntryPoint().(BlockStmt).getStmt(169)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(169).getFollowingStmt()=target_8)
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_11(Variable vreader_383, ExprStmt target_21, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("redisReaderFree")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
		and (func.getEntryPoint().(BlockStmt).getStmt(173)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(173).getFollowingStmt()=target_11)
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_12(Variable vtests, PrefixIncrExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vtests
}

predicate func_13(Variable vtests, PrefixIncrExpr target_13) {
		target_13.getOperand().(VariableAccess).getTarget()=vtests
}

predicate func_14(Variable vreader_383, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("redisReaderFree")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
}

predicate func_15(Variable vreader_383, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreader_383
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("redisReaderCreate")
}

predicate func_16(Variable vreader_383, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fn"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreader_383
		and target_16.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_17(Variable vreader_383, Variable vret_385, LogicalAndExpr target_17) {
		target_17.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_385
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcasecmp")
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="errstr"
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreader_383
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Multi-bulk length out of range"
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Variable vfails, ExprStmt target_18) {
		target_18.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vfails
}

predicate func_19(Variable vfails, ExprStmt target_19) {
		target_19.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vfails
}

predicate func_20(Variable vreader_383, Variable vreply_384, Variable vret_385, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_385
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("redisReaderGetReply")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vreply_384
}

predicate func_21(Variable vreader_383, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("redisReaderFree")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreader_383
}

predicate func_22(Variable vreply_384, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("freeReplyObject")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreply_384
}

from Function func, Variable vreader_383, Variable vreply_384, Variable vret_385, Variable vtests, Variable vfails, PrefixIncrExpr target_12, PrefixIncrExpr target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, LogicalAndExpr target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22
where
not func_0(vtests, target_12, target_13)
and not func_1(func)
and not func_2(func)
and not func_3(vreader_383, target_14, func)
and not func_4(vreader_383, func)
and not func_5(vreader_383, vret_385, vfails, target_15, target_16, target_17, target_18, target_19, func)
and not func_7(vreader_383, target_20, func)
and not func_8(vreader_383, vreply_384, vret_385, target_21, target_22, func)
and not func_11(vreader_383, target_21, func)
and func_12(vtests, target_12)
and func_13(vtests, target_13)
and func_14(vreader_383, target_14)
and func_15(vreader_383, target_15)
and func_16(vreader_383, target_16)
and func_17(vreader_383, vret_385, target_17)
and func_18(vfails, target_18)
and func_19(vfails, target_19)
and func_20(vreader_383, vreply_384, vret_385, target_20)
and func_21(vreader_383, target_21)
and func_22(vreply_384, target_22)
and vreader_383.getType().hasName("redisReader *")
and vreply_384.getType().hasName("void *")
and vret_385.getType().hasName("int")
and vtests.getType().hasName("int")
and vfails.getType().hasName("int")
and vreader_383.getParentScope+() = func
and vreply_384.getParentScope+() = func
and vret_385.getParentScope+() = func
and not vtests.getParentScope+() = func
and not vfails.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
