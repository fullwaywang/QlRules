/**
 * @name wireshark-7b6e197da4c497e229ed3ebf6952bae5c426a820-call_dissector_work
 * @id cpp/wireshark/7b6e197da4c497e229ed3ebf6952bae5c426a820/call-dissector-work
 * @description wireshark-7b6e197da4c497e229ed3ebf6952bae5c426a820-epan/packet.c-call_dissector_work CVE-2019-12295
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsaved_layers_len_711, ExprStmt target_1, RelationalOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsaved_layers_len_711
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_strdup_printf")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_packet_scope")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%u: failed assertion \"%s\""
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(4).(StringLiteral).getValue()="saved_layers_len < 500"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsaved_layers_len_711, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsaved_layers_len_711
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wmem_list_count")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="layers"
}

predicate func_2(Variable vsaved_layers_len_711, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(FunctionCall).getTarget().hasName("wmem_list_count")
		and target_2.getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="layers"
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vsaved_layers_len_711
}

from Function func, Variable vsaved_layers_len_711, ExprStmt target_1, RelationalOperation target_2
where
not func_0(vsaved_layers_len_711, target_1, target_2, func)
and func_1(vsaved_layers_len_711, target_1)
and func_2(vsaved_layers_len_711, target_2)
and vsaved_layers_len_711.getType().hasName("guint")
and vsaved_layers_len_711.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
