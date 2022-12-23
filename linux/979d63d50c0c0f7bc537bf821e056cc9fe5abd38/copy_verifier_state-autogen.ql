/**
 * @name linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-copy_verifier_state
 * @id cpp/linux/979d63d50c0c0f7bc537bf821e056cc9fe5abd38/copy_verifier_state
 * @description linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-copy_verifier_state 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_state_702, Parameter vsrc_703, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_state_702
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_703
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vdst_state_702) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="frame"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdst_state_702)
}

predicate func_2(Parameter vsrc_703) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="curframe"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsrc_703)
}

from Function func, Parameter vdst_state_702, Parameter vsrc_703
where
not func_0(vdst_state_702, vsrc_703, func)
and vdst_state_702.getType().hasName("bpf_verifier_state *")
and func_1(vdst_state_702)
and vsrc_703.getType().hasName("const bpf_verifier_state *")
and func_2(vsrc_703)
and vdst_state_702.getParentScope+() = func
and vsrc_703.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
