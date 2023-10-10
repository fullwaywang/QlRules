/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-svc_generic_init_request
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/svc-generic-init-request
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-svc_generic_init_request 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vprocp_1178) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="pc_argsize"
		and target_0.getQualifier().(VariableAccess).getTarget()=vprocp_1178)
}

from Function func, Variable vprocp_1178
where
func_0(vprocp_1178)
and vprocp_1178.getType().hasName("const svc_procedure *")
and vprocp_1178.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
