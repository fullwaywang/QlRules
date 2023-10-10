/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_open
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/i915_gem_context_open
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-i915_gem_context_open 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_priv_625, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__mutex_init")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr_lock"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_priv_625
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="&file_priv->context_idr_lock"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("lock_class_key")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vi915_622, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="struct_mutex"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="drm"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi915_622
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3))
}

predicate func_4(Variable vfile_priv_625, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("mutex_destroy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr_lock"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_priv_625
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vi915_622) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="drm"
		and target_5.getQualifier().(VariableAccess).getTarget()=vi915_622)
}

predicate func_6(Variable vfile_priv_625) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="context_idr"
		and target_6.getQualifier().(VariableAccess).getTarget()=vfile_priv_625)
}

predicate func_7(Variable vfile_priv_625, Variable vctx_626) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("gem_context_register")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vctx_626
		and target_7.getArgument(1).(VariableAccess).getTarget()=vfile_priv_625)
}

from Function func, Parameter vi915_622, Variable vfile_priv_625, Variable vctx_626
where
not func_0(vfile_priv_625, func)
and not func_3(vi915_622, func)
and not func_4(vfile_priv_625, func)
and vi915_622.getType().hasName("drm_i915_private *")
and func_5(vi915_622)
and vfile_priv_625.getType().hasName("drm_i915_file_private *")
and func_6(vfile_priv_625)
and func_7(vfile_priv_625, vctx_626)
and vctx_626.getType().hasName("i915_gem_context *")
and vi915_622.getParentScope+() = func
and vfile_priv_625.getParentScope+() = func
and vctx_626.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
