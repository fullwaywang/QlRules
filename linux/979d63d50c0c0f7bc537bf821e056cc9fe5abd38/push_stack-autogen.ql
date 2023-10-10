/**
 * @name linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-push_stack
 * @id cpp/linux/979d63d50c0c0f7bc537bf821e056cc9fe5abd38/push_stack
 * @description linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-push_stack 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable velem_760, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="speculative"
		and target_0.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="st"
		and target_0.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velem_760
		and target_0.getExpr().(AssignOrExpr).getRValue().(VariableAccess).getType().hasName("bool")
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Variable velem_760) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="st"
		and target_1.getQualifier().(VariableAccess).getTarget()=velem_760)
}

from Function func, Variable velem_760
where
not func_0(velem_760, func)
and velem_760.getType().hasName("bpf_verifier_stack_elem *")
and func_1(velem_760)
and velem_760.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
