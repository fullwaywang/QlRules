/**
 * @name linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-states_equal
 * @id cpp/linux/979d63d50c0c0f7bc537bf821e056cc9fe5abd38/states_equal
 * @description linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-states_equal 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vcur_5495, Parameter vold_5494, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_5494
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_5495
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcur_5495) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="curframe"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcur_5495)
}

predicate func_2(Parameter vold_5494) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="curframe"
		and target_2.getQualifier().(VariableAccess).getTarget()=vold_5494)
}

from Function func, Parameter vcur_5495, Parameter vold_5494
where
not func_0(vcur_5495, vold_5494, func)
and vcur_5495.getType().hasName("bpf_verifier_state *")
and func_1(vcur_5495)
and vold_5494.getType().hasName("bpf_verifier_state *")
and func_2(vold_5494)
and vcur_5495.getParentScope+() = func
and vold_5494.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
