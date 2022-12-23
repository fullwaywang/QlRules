/**
 * @name linux-73c3ed7495c67b8fbdc31cf58e6ca8757df31a33-malidp_crtc_reset
 * @id cpp/linux/73c3ed7495c67b8fbdc31cf58e6ca8757df31a33/malidp-crtc-reset
 * @description linux-73c3ed7495c67b8fbdc31cf58e6ca8757df31a33-malidp_crtc_reset 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcrtc_482, Variable vstate_484, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vstate_484
		and target_0.getThen() instanceof ExprStmt
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__drm_atomic_helper_crtc_reset")
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrtc_482
		and target_0.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcrtc_482, Variable vstate_484, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__drm_atomic_helper_crtc_reset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrtc_482
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_484
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vcrtc_482) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcrtc_482)
}

predicate func_3(Variable vstate_484) {
	exists(PointerDereferenceExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vstate_484)
}

from Function func, Parameter vcrtc_482, Variable vstate_484
where
not func_0(vcrtc_482, vstate_484, func)
and func_1(vcrtc_482, vstate_484, func)
and vcrtc_482.getType().hasName("drm_crtc *")
and func_2(vcrtc_482)
and vstate_484.getType().hasName("malidp_crtc_state *")
and func_3(vstate_484)
and vcrtc_482.getParentScope+() = func
and vstate_484.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
