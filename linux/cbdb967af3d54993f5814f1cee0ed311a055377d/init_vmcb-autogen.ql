/**
 * @name linux-cbdb967af3d54993f5814f1cee0ed311a055377d-init_vmcb
 * @id cpp/linux/cbdb967af3d54993f5814f1cee0ed311a055377d/init_vmcb
 * @description linux-cbdb967af3d54993f5814f1cee0ed311a055377d-init_vmcb CVE-2015-8104
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsvm_1001, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("set_exception_intercept")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvm_1001
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsvm_1001) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("set_exception_intercept")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vsvm_1001
		and target_1.getArgument(1).(Literal).getValue()="17")
}

from Function func, Parameter vsvm_1001
where
not func_0(vsvm_1001, func)
and vsvm_1001.getType().hasName("vcpu_svm *")
and func_1(vsvm_1001)
and vsvm_1001.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
