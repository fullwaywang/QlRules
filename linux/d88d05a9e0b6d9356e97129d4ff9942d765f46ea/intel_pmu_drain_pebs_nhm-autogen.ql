/**
 * @name linux-d88d05a9e0b6d9356e97129d4ff9942d765f46ea-intel_pmu_drain_pebs_nhm
 * @id cpp/linux/d88d05a9e0b6d9356e97129d4ff9942d765f46ea/intel-pmu-drain-pebs-nhm
 * @description linux-d88d05a9e0b6d9356e97129d4ff9942d765f46ea-intel_pmu_drain_pebs_nhm 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_1989, Variable vpebs_status_1990) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_1989
		and target_0.getRValue() instanceof PointerFieldAccess
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpebs_status_1990)
}

predicate func_1(Variable vcpuc_1959, Variable vpebs_status_1990) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="pebs_enabled"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcpuc_1959
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpebs_status_1990)
}

predicate func_2(Variable vp_1989) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="status"
		and target_2.getQualifier().(VariableAccess).getTarget()=vp_1989)
}

from Function func, Variable vcpuc_1959, Variable vp_1989, Variable vpebs_status_1990
where
not func_0(vp_1989, vpebs_status_1990)
and func_1(vcpuc_1959, vpebs_status_1990)
and vcpuc_1959.getType().hasName("cpu_hw_events *")
and vp_1989.getType().hasName("pebs_record_nhm *")
and func_2(vp_1989)
and vpebs_status_1990.getType().hasName("u64")
and vcpuc_1959.getParentScope+() = func
and vp_1989.getParentScope+() = func
and vpebs_status_1990.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
