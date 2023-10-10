/**
 * @name libssh-203818608ac8a83d68098f008306c3a568ac4cac-ssh_packet_socket_callback
 * @id cpp/libssh/203818608ac8a83d68098f008306c3a568ac4cac/ssh-packet-socket-callback
 * @description libssh-203818608ac8a83d68098f008306c3a568ac4cac-src/packet.c-ssh_packet_socket_callback CVE-2018-10933
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsession_145, PointerFieldAccess target_4, ValueFieldAccess target_5, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ssh_packet_filter_result_e")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssh_packet_incoming_filter")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_145
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vsession_145, PointerFieldAccess target_4, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ssh_packet_process")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_145
		and target_2.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="type"
		and target_2.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="in_packet"
		and target_2.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_145
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
}

predicate func_3(Function func, LabelStmt target_3) {
		target_3.toString() = "label ...:"
		and target_3.getName() ="error"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vsession_145, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="packet_state"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsession_145
}

predicate func_5(Variable vsession_145, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="type"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="in_packet"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_145
}

from Function func, Variable vsession_145, ExprStmt target_2, LabelStmt target_3, PointerFieldAccess target_4, ValueFieldAccess target_5
where
not func_0(vsession_145, target_4, target_5, target_2)
and func_2(vsession_145, target_4, target_2)
and func_3(func, target_3)
and func_4(vsession_145, target_4)
and func_5(vsession_145, target_5)
and vsession_145.getType().hasName("ssh_session")
and vsession_145.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
