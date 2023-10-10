/**
 * @name linux-54a20552e1eae07aa240fa370a0293e006b5faed-init_vmcb
 * @id cpp/linux/54a20552e1eae07aa240fa370a0293e006b5faed/init_vmcb
 * @description linux-54a20552e1eae07aa240fa370a0293e006b5faed-init_vmcb CVE-2015-5307
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsvm_1001, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("set_exception_intercept")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvm_1001
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="17"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsvm_1001) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("set_exception_intercept")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vsvm_1001
		and target_1.getArgument(1).(Literal).getValue()="18")
}

from Function func, Parameter vsvm_1001
where
not func_0(vsvm_1001, func)
and vsvm_1001.getType().hasName("vcpu_svm *")
and func_1(vsvm_1001)
and vsvm_1001.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
