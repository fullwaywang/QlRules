/**
 * @name tor-890ae4fb1adfa13e37aaf5261e089e8c195a75cf-dirvote_add_signatures_to_pending_consensus
 * @id cpp/tor/890ae4fb1adfa13e37aaf5261e089e8c195a75cf/dirvote-add-signatures-to-pending-consensus
 * @description tor-890ae4fb1adfa13e37aaf5261e089e8c195a75cf-src/feature/dirauth/dirvote.c-dirvote_add_signatures_to_pending_consensus CVE-2021-28090
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpc_3478, ExprStmt target_4, FunctionCall target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("find_str_at_start_of_line")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="body"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_3478
		and target_0.getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpc_3478, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="body"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpc_3478
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vpc_3478, FunctionCall target_3) {
		target_3.getTarget().hasName("strstr")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="body"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_3478
		and target_3.getArgument(1) instanceof StringLiteral
}

predicate func_4(Parameter vpc_3478, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="body"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_3478
}

predicate func_5(Parameter vpc_3478, FunctionCall target_5) {
		target_5.getTarget().hasName("networkstatus_parse_vote_from_string")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="body"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpc_3478
		and target_5.getArgument(1).(Literal).getValue()="0"
}

from Function func, Parameter vpc_3478, PointerFieldAccess target_1, FunctionCall target_3, ExprStmt target_4, FunctionCall target_5
where
not func_0(vpc_3478, target_4, target_5)
and func_1(vpc_3478, target_1)
and func_3(vpc_3478, target_3)
and func_4(vpc_3478, target_4)
and func_5(vpc_3478, target_5)
and vpc_3478.getType().hasName("pending_consensus_t *")
and vpc_3478.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
