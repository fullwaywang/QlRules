/**
 * @name linux-bcd0f93353326954817a4f9fa55ec57fb38acbb0-pep_sock_accept
 * @id cpp/linux/bcd0f93353326954817a4f9fa55ec57fb38acbb0/pep-sock-accept
 * @description linux-bcd0f93353326954817a4f9fa55ec57fb38acbb0-pep_sock_accept 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_770, Parameter vsk_762) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__sock_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_762
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_770)
}

predicate func_1(Variable vnewpn_765, Parameter vsk_762) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="listener"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewpn_765
		and target_1.getRValue().(VariableAccess).getTarget()=vsk_762)
}

from Function func, Variable vnewpn_765, Variable verr_770, Parameter vsk_762
where
not func_0(verr_770, vsk_762)
and verr_770.getType().hasName("int")
and vsk_762.getType().hasName("sock *")
and func_1(vnewpn_765, vsk_762)
and vnewpn_765.getParentScope+() = func
and verr_770.getParentScope+() = func
and vsk_762.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
