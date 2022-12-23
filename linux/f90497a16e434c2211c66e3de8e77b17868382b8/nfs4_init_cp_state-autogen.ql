/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_init_cp_state
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs4-init-cp-state
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_init_cp_state 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstid_965) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="stid"
		and target_0.getQualifier().(VariableAccess).getTarget()=vstid_965)
}

predicate func_3(Parameter vstid_965, Parameter vsc_type_966) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vsc_type_966
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sc_type"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstid_965)
}

from Function func, Parameter vstid_965, Parameter vsc_type_966
where
func_0(vstid_965)
and func_3(vstid_965, vsc_type_966)
and vstid_965.getType().hasName("copy_stateid_t *")
and vsc_type_966.getType().hasName("unsigned char")
and vstid_965.getParentScope+() = func
and vsc_type_966.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
