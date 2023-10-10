/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_resume_port
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-resume-port
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_resume_port function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vrc_64, Variable vport_45) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sas_destruct_devices")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_45
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrc_64)
}

predicate func_2(Variable vdev_44, Variable vport_45) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sas_unregister_dev")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vport_45
		and target_2.getArgument(1).(VariableAccess).getTarget()=vdev_44)
}

from Function func, Variable vrc_64, Variable vdev_44, Variable vport_45
where
not func_1(vrc_64, vport_45)
and vrc_64.getType().hasName("int")
and vport_45.getType().hasName("asd_sas_port *")
and func_2(vdev_44, vport_45)
and vrc_64.getParentScope+() = func
and vdev_44.getParentScope+() = func
and vport_45.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
