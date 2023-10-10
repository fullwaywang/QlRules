/**
 * @name wireshark-c557bb0910be271e49563756411a690a1bc53ce5-dissect_rpcap_heur_tcp
 * @id cpp/wireshark/c557bb0910be271e49563756411a690a1bc53ce5/dissect-rpcap-heur-tcp
 * @description wireshark-c557bb0910be271e49563756411a690a1bc53ce5-epan/dissectors/packet-rpcap.c-dissect_rpcap_heur_tcp CVE-2019-9214
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconversation_1162, FunctionCall target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vconversation_1162
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpinfo_1153, Variable vconversation_1162, Variable vrpcap_tcp_handle, FunctionCall target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("conversation_set_dissector_from_frame_number")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconversation_1162
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="num"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_1153
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrpcap_tcp_handle
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(FunctionCall target_2) {
		target_2.getTarget().hasName("check_rpcap_heur")
		and target_2.getArgument(1).(NotExpr).getValue()="1"
}

from Function func, Parameter vpinfo_1153, Variable vconversation_1162, Variable vrpcap_tcp_handle, ExprStmt target_1, FunctionCall target_2
where
not func_0(vconversation_1162, target_2, target_1)
and func_1(vpinfo_1153, vconversation_1162, vrpcap_tcp_handle, target_2, target_1)
and func_2(target_2)
and vpinfo_1153.getType().hasName("packet_info *")
and vconversation_1162.getType().hasName("conversation_t *")
and vrpcap_tcp_handle.getType().hasName("dissector_handle_t")
and vpinfo_1153.getParentScope+() = func
and vconversation_1162.getParentScope+() = func
and not vrpcap_tcp_handle.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
