/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_destroy_ioctl
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/i915_gem_context_destroy_ioctl
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_destroy_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_876) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("i915_gem_context_put")
		and not target_0.getTarget().hasName("mutex_unlock")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctx_876)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("mutex_lock_nested")
		and target_4.getArgument(0) instanceof AddressOfExpr
		and target_4.getArgument(1).(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vargs_874) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="ctx_id"
		and target_5.getQualifier().(VariableAccess).getTarget()=vargs_874
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_6(Parameter vdev_871) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="struct_mutex"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_871
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mutex_lock_interruptible_nested")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_8(Function func) {
	exists(DeclStmt target_8 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable vfile_priv_875) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("i915_gem_context_lookup")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vfile_priv_875
		and target_9.getArgument(1) instanceof PointerFieldAccess)
}

predicate func_10(Variable vret_877) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vret_877
		and target_10.getRValue().(FunctionCall).getTarget().hasName("mutex_lock_interruptible_nested")
		and target_10.getRValue().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_10.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_13(Variable vctx_876) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="user_handle"
		and target_13.getQualifier().(VariableAccess).getTarget()=vctx_876)
}

predicate func_14(Function func) {
	exists(LabelStmt target_14 |
		target_14.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_15(Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15)
}

predicate func_16(Variable vfile_priv_875) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="context_idr"
		and target_16.getQualifier().(VariableAccess).getTarget()=vfile_priv_875)
}

from Function func, Parameter vdev_871, Variable vargs_874, Variable vfile_priv_875, Variable vctx_876, Variable vret_877
where
func_0(vctx_876)
and not func_4(func)
and func_5(vargs_874)
and func_6(vdev_871)
and func_8(func)
and func_9(vfile_priv_875)
and func_10(vret_877)
and func_13(vctx_876)
and func_14(func)
and func_15(func)
and vdev_871.getType().hasName("drm_device *")
and vargs_874.getType().hasName("drm_i915_gem_context_destroy *")
and vfile_priv_875.getType().hasName("drm_i915_file_private *")
and func_16(vfile_priv_875)
and vctx_876.getType().hasName("i915_gem_context *")
and vret_877.getType().hasName("int")
and vdev_871.getParentScope+() = func
and vargs_874.getParentScope+() = func
and vfile_priv_875.getParentScope+() = func
and vctx_876.getParentScope+() = func
and vret_877.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
