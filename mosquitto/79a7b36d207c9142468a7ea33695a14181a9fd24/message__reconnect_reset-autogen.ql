/**
 * @name mosquitto-79a7b36d207c9142468a7ea33695a14181a9fd24-message__reconnect_reset
 * @id cpp/mosquitto/79a7b36d207c9142468a7ea33695a14181a9fd24/message--reconnect-reset
 * @description mosquitto-79a7b36d207c9142468a7ea33695a14181a9fd24-lib/messages_mosq.c-message__reconnect_reset CVE-2017-7655
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmessage_156, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vmessage_156
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmessage_156
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_156
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmessage_156, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmessage_156
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmessage_156
}

predicate func_2(Variable vmessage_156, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmessage_156
}

from Function func, Variable vmessage_156, ExprStmt target_1, ExprStmt target_2
where
not func_0(vmessage_156, target_2)
and func_1(vmessage_156, target_1)
and func_2(vmessage_156, target_2)
and vmessage_156.getType().hasName("mosquitto_message_all *")
and vmessage_156.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
