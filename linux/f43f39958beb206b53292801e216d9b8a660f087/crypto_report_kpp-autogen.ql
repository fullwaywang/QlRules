/**
 * @name linux-f43f39958beb206b53292801e216d9b8a660f087-crypto_report_kpp
 * @id cpp/linux/f43f39958beb206b53292801e216d9b8a660f087/crypto-report-kpp
 * @description linux-f43f39958beb206b53292801e216d9b8a660f087-crypto_report_kpp 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strncpy")
		and target_0.getArgument(0) instanceof ValueFieldAccess
		and target_0.getArgument(1) instanceof StringLiteral
		and target_0.getArgument(2) instanceof SizeofExprOperator
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vrkpp_148) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="type"
		and target_1.getQualifier().(VariableAccess).getTarget()=vrkpp_148)
}

predicate func_2(Variable vrkpp_148) {
	exists(SizeofExprOperator target_2 |
		target_2.getValue()="64"
		and target_2.getExprOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_2.getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrkpp_148)
}

predicate func_3(Function func) {
	exists(StringLiteral target_3 |
		target_3.getValue()="kpp"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("strlcpy")
		and target_4.getArgument(0) instanceof ValueFieldAccess
		and target_4.getArgument(1) instanceof StringLiteral
		and target_4.getArgument(2) instanceof SizeofExprOperator
		and target_4.getEnclosingFunction() = func)
}

from Function func, Variable vrkpp_148
where
not func_0(func)
and func_1(vrkpp_148)
and func_2(vrkpp_148)
and func_3(func)
and func_4(func)
and vrkpp_148.getType().hasName("crypto_report_kpp")
and vrkpp_148.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
