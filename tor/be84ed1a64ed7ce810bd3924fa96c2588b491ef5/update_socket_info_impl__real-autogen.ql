/**
 * @name tor-be84ed1a64ed7ce810bd3924fa96c2588b491ef5-update_socket_info_impl__real
 * @id cpp/tor/be84ed1a64ed7ce810bd3924fa96c2588b491ef5/update-socket-info-impl--real
 * @description tor-be84ed1a64ed7ce810bd3924fa96c2588b491ef5-src/or/scheduler_kist.c-update_socket_info_impl__real CVE-2019-8955
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vent_190, ExprStmt target_2, MulExpr target_3) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand() instanceof SubExpr
		and target_0.getRightOperand().(FunctionCall).getTarget().hasName("channel_outbuf_length")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="chan"
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsock_buf_size_factor, Parameter vent_190, SubExpr target_1) {
		target_1.getLeftOperand().(FunctionCall).getTarget().hasName("clamp_double_to_int64")
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cwnd"
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="mss"
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_1.getLeftOperand().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsock_buf_size_factor
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="notsent"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

predicate func_2(Parameter vent_190, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cwnd"
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="unacked"
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="mss"
		and target_2.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
}

predicate func_3(Variable vsock_buf_size_factor, Parameter vent_190, MulExpr target_3) {
		target_3.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cwnd"
		and target_3.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="mss"
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_190
		and target_3.getRightOperand().(VariableAccess).getTarget()=vsock_buf_size_factor
}

from Function func, Variable vsock_buf_size_factor, Parameter vent_190, SubExpr target_1, ExprStmt target_2, MulExpr target_3
where
not func_0(vent_190, target_2, target_3)
and func_1(vsock_buf_size_factor, vent_190, target_1)
and func_2(vent_190, target_2)
and func_3(vsock_buf_size_factor, vent_190, target_3)
and vsock_buf_size_factor.getType().hasName("double")
and vent_190.getType().hasName("socket_table_ent_t *")
and not vsock_buf_size_factor.getParentScope+() = func
and vent_190.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
