/**
 * @name tor-665baf5ed5c6186d973c46cdea165c0548027350-entry_guard_obeys_restriction
 * @id cpp/tor/665baf5ed5c6186d973c46cdea165c0548027350/entry-guard-obeys-restriction
 * @description tor-665baf5ed5c6186d973c46cdea165c0548027350-src/or/entrynodes.c-entry_guard_obeys_restriction CVE-2017-0377
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vguard_1436, NotExpr target_1, NotExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("const node_t *")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("guard_in_node_family")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vguard_1436
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const node_t *")
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vguard_1436, NotExpr target_1) {
		target_1.getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vguard_1436
}

predicate func_2(Parameter vguard_1436, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("tor_memeq")
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="identity"
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vguard_1436
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="exclude_id"
		and target_2.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="20"
}

from Function func, Parameter vguard_1436, NotExpr target_1, NotExpr target_2
where
not func_0(vguard_1436, target_1, target_2, func)
and func_1(vguard_1436, target_1)
and func_2(vguard_1436, target_2)
and vguard_1436.getType().hasName("const entry_guard_t *")
and vguard_1436.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
