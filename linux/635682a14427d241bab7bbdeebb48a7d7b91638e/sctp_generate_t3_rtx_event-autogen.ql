/**
 * @name linux-635682a14427d241bab7bbdeebb48a7d7b91638e-sctp_generate_t3_rtx_event
 * @id cpp/linux/635682a14427d241bab7bbdeebb48a7d7b91638e/sctp_generate_t3_rtx_event
 * @description linux-635682a14427d241bab7bbdeebb48a7d7b91638e-sctp_generate_t3_rtx_event 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getVariable().getInitializer().(Initializer).getExpr() instanceof ValueFieldAccess
		and target_0.getDeclaration().getParentScope+() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("sock_net")
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sock *")
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_1)
}

predicate func_7(Variable vasoc_246) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="sk"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="base"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasoc_246)
}

from Function func, Variable vasoc_246
where
not func_0(func)
and not func_1(func)
and func_7(vasoc_246)
and vasoc_246.getType().hasName("sctp_association *")
and vasoc_246.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
