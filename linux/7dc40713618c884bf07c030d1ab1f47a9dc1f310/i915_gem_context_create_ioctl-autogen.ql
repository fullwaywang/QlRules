/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_create_ioctl
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/i915_gem_context_create_ioctl
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_create_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_822) {
	exists(ReturnStmt target_0 |
		target_0.getExpr() instanceof FunctionCall
		and target_0.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_0.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_822)
}

predicate func_1(Parameter vdev_816) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("mutex_lock_nested")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="struct_mutex"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_816
		and target_1.getArgument(1).(Literal).getValue()="0")
}

predicate func_2(Variable vctx_822) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("PTR_ERR")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctx_822)
}

predicate func_3(Variable vret_823) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vret_823
		and target_3.getRValue() instanceof FunctionCall)
}

predicate func_4(Variable vctx_822) {
	exists(GotoStmt target_4 |
		target_4.toString() = "goto ..."
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_822)
}

predicate func_5(Function func) {
	exists(LabelStmt target_5 |
		target_5.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vdev_816) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("i915_mutex_lock_interruptible")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vdev_816)
}

from Function func, Variable vctx_822, Variable vret_823, Parameter vdev_816
where
not func_0(vctx_822)
and not func_1(vdev_816)
and func_2(vctx_822)
and func_3(vret_823)
and func_4(vctx_822)
and func_5(func)
and vctx_822.getType().hasName("i915_gem_context *")
and vret_823.getType().hasName("int")
and vdev_816.getType().hasName("drm_device *")
and func_6(vdev_816)
and vctx_822.getParentScope+() = func
and vret_823.getParentScope+() = func
and vdev_816.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
