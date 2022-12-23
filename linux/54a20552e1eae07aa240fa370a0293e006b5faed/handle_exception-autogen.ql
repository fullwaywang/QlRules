/**
 * @name linux-54a20552e1eae07aa240fa370a0293e006b5faed-handle_exception
 * @id cpp/linux/54a20552e1eae07aa240fa370a0293e006b5faed/handle_exception
 * @description linux-54a20552e1eae07aa240fa370a0293e006b5faed-handle_exception CVE-2015-5307
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SwitchCase target_0 |
		target_0.getExpr().(Literal).getValue()="17"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable verror_code_5197, Parameter vvcpu_5193) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("kvm_queue_exception_e")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_5193
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="17"
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=verror_code_5197)
}

predicate func_3(Variable vex_no_5197, Variable verror_code_5197, Parameter vvcpu_5193) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("handle_rmode_exception")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vvcpu_5193
		and target_3.getArgument(1).(VariableAccess).getTarget()=vex_no_5197
		and target_3.getArgument(2).(VariableAccess).getTarget()=verror_code_5197)
}

from Function func, Variable vex_no_5197, Variable verror_code_5197, Parameter vvcpu_5193
where
not func_0(func)
and not func_1(verror_code_5197, vvcpu_5193)
and verror_code_5197.getType().hasName("u32")
and func_3(vex_no_5197, verror_code_5197, vvcpu_5193)
and vvcpu_5193.getType().hasName("kvm_vcpu *")
and vex_no_5197.getParentScope+() = func
and verror_code_5197.getParentScope+() = func
and vvcpu_5193.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
