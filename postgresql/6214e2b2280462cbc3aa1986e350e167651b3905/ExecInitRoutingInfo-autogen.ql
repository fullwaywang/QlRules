/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecInitRoutingInfo
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecInitRoutingInfo
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execPartition.c-ExecInitRoutingInfo CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpartRelInfo_951, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="ri_PartitionRoot"
		and target_0.getQualifier().(VariableAccess).getTarget()=vpartRelInfo_951
}

from Function func, Parameter vpartRelInfo_951, PointerFieldAccess target_0
where
func_0(vpartRelInfo_951, target_0)
and vpartRelInfo_951.getType().hasName("ResultRelInfo *")
and vpartRelInfo_951.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
