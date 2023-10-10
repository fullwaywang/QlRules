/**
 * @name linux-ecec76885bcfe3294685dc363fd1273df0d5d65f-free_nested
 * @id cpp/linux/ecec76885bcfe3294685dc363fd1273df0d5d65f/free-nested
 * @description linux-ecec76885bcfe3294685dc363fd1273df0d5d65f-free_nested CVE-2019-7221
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvmx_209, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("hrtimer_cancel")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="preemption_timer"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="nested"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmx_209
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vvmx_209) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="nested"
		and target_1.getQualifier().(VariableAccess).getTarget()=vvmx_209)
}

from Function func, Variable vvmx_209
where
not func_0(vvmx_209, func)
and vvmx_209.getType().hasName("vcpu_vmx *")
and func_1(vvmx_209)
and vvmx_209.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
