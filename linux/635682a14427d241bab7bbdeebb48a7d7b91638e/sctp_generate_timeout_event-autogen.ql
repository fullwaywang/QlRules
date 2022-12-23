/**
 * @name linux-635682a14427d241bab7bbdeebb48a7d7b91638e-sctp_generate_timeout_event
 * @id cpp/linux/635682a14427d241bab7bbdeebb48a7d7b91638e/sctp_generate_timeout_event
 * @description linux-635682a14427d241bab7bbdeebb48a7d7b91638e-sctp_generate_timeout_event 
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
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_1)
}

predicate func_7(Parameter vasoc_285) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="sk"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="base"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasoc_285)
}

predicate func_8(Parameter vasoc_285) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="base"
		and target_8.getQualifier().(VariableAccess).getTarget()=vasoc_285)
}

from Function func, Parameter vasoc_285
where
not func_0(func)
and not func_1(func)
and func_7(vasoc_285)
and func_8(vasoc_285)
and vasoc_285.getType().hasName("sctp_association *")
and vasoc_285.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
