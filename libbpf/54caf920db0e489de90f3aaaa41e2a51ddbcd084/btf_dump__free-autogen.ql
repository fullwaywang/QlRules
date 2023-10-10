/**
 * @name libbpf-54caf920db0e489de90f3aaaa41e2a51ddbcd084-btf_dump__free
 * @id cpp/libbpf/54caf920db0e489de90f3aaaa41e2a51ddbcd084/btf-dump--free
 * @description libbpf-54caf920db0e489de90f3aaaa41e2a51ddbcd084-src/btf_dump.c-btf_dump__free CVE-2022-3534
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vd_222, FunctionCall target_0) {
		target_0.getTarget().hasName("hashmap__free")
		and not target_0.getTarget().hasName("btf_dump_free_names")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="type_names"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_222
}

predicate func_1(Parameter vd_222, FunctionCall target_1) {
		target_1.getTarget().hasName("hashmap__free")
		and not target_1.getTarget().hasName("btf_dump_free_names")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="ident_names"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_222
}

from Function func, Parameter vd_222, FunctionCall target_0, FunctionCall target_1
where
func_0(vd_222, target_0)
and func_1(vd_222, target_1)
and vd_222.getType().hasName("btf_dump *")
and vd_222.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
