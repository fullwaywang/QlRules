/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-io_session_event
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/io-session-event
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-server.c-io_session_event CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_142, FunctionCall target_0) {
		target_0.getTarget().hasName("sdp_svcdb_collect_all")
		and not target_0.getTarget().hasName("sdp_cstate_cleanup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsk_142
}

predicate func_1(BitwiseAndExpr target_11, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="cleanup"
		and target_1.getParent().(IfStmt).getCondition()=target_11
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(LogicalOrExpr target_12, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="cleanup"
		and target_2.getParent().(IfStmt).getCondition()=target_12
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(BitwiseAndExpr target_11, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="cleanup"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(LabelStmt target_4 |
		target_4.toString() = "label ...:"
		and target_4.getName() ="cleanup"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_4))
}

predicate func_5(BitwiseAndExpr target_11, Function func, ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vsk_142, RelationalOperation target_13, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("sdp_svcdb_collect_all")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_142
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_7(Variable vbuf_141, RelationalOperation target_13, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_141
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_8(Variable vsk_142, LogicalOrExpr target_12, ExprStmt target_14, ExprStmt target_15, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("sdp_svcdb_collect_all")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_142
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_9(LogicalOrExpr target_12, Function func, ReturnStmt target_9) {
		target_9.getExpr().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_9.getEnclosingFunction() = func
}

predicate func_10(RelationalOperation target_13, Function func, ReturnStmt target_10) {
		target_10.getExpr().(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_10.getEnclosingFunction() = func
}

predicate func_11(BitwiseAndExpr target_11) {
		target_11.getRightOperand().(BitwiseOrExpr).getValue()="24"
}

predicate func_12(LogicalOrExpr target_12) {
		target_12.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_12.getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofTypeOperator).getValue()="5"
}

predicate func_13(RelationalOperation target_13) {
		 (target_13 instanceof GEExpr or target_13 instanceof LEExpr)
		and target_13.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vsk_142, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("recv")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_142
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="5"
}

predicate func_15(Variable vbuf_141, Variable vsk_142, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("recv")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_142
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_141
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

from Function func, Variable vbuf_141, Variable vsk_142, FunctionCall target_0, ReturnStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ReturnStmt target_9, ReturnStmt target_10, BitwiseAndExpr target_11, LogicalOrExpr target_12, RelationalOperation target_13, ExprStmt target_14, ExprStmt target_15
where
func_0(vsk_142, target_0)
and not func_1(target_11, func)
and not func_2(target_12, func)
and not func_3(target_11, func)
and not func_4(func)
and func_5(target_11, func, target_5)
and func_6(vsk_142, target_13, target_6)
and func_7(vbuf_141, target_13, target_7)
and func_8(vsk_142, target_12, target_14, target_15, target_8)
and func_9(target_12, func, target_9)
and func_10(target_13, func, target_10)
and func_11(target_11)
and func_12(target_12)
and func_13(target_13)
and func_14(vsk_142, target_14)
and func_15(vbuf_141, vsk_142, target_15)
and vbuf_141.getType().hasName("uint8_t *")
and vsk_142.getType().hasName("int")
and vbuf_141.getParentScope+() = func
and vsk_142.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
