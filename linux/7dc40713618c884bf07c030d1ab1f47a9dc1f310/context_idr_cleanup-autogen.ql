/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-context_idr_cleanup
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/context_idr_cleanup
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-context_idr_cleanup 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vp_580, Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vp_580
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vctx_582) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vctx_582
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("context_close"))
}

from Function func, Parameter vp_580, Variable vctx_582
where
func_1(vp_580, func)
and func_2(vctx_582)
and vp_580.getType().hasName("void *")
and vctx_582.getType().hasName("i915_gem_context *")
and vp_580.getParentScope+() = func
and vctx_582.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
