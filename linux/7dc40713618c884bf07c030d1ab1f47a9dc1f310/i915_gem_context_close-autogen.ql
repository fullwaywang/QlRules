/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_close
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/i915_gem_context_close
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_close 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_priv_660, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_destroy")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_priv_660
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Variable vfile_priv_660) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="context_idr"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfile_priv_660)
}

from Function func, Variable vfile_priv_660
where
not func_0(vfile_priv_660, func)
and vfile_priv_660.getType().hasName("drm_i915_file_private *")
and func_1(vfile_priv_660)
and vfile_priv_660.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
