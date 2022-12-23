/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_dupcook_a
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-dupcook-a
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_dupcook_a CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vep_1844, Parameter vasoc_1845, Parameter vchunk_1846, Parameter vcommands_1847, Parameter vnet_1843) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_do_9_2_reshutack")
		and not target_0.getTarget().hasName("__sctp_sf_do_9_2_reshutack")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_1843
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_1844
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_1845
		and target_0.getArgument(3).(FunctionCall).getTarget().hasName("SCTP_ST_CHUNK")
		and target_0.getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="chunk_hdr"
		and target_0.getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchunk_1846
		and target_0.getArgument(4).(VariableAccess).getTarget()=vchunk_1846
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_1847)
}

from Function func, Parameter vep_1844, Parameter vasoc_1845, Parameter vchunk_1846, Parameter vcommands_1847, Parameter vnet_1843
where
func_0(vep_1844, vasoc_1845, vchunk_1846, vcommands_1847, vnet_1843)
and vep_1844.getType().hasName("const sctp_endpoint *")
and vasoc_1845.getType().hasName("const sctp_association *")
and vchunk_1846.getType().hasName("sctp_chunk *")
and vcommands_1847.getType().hasName("sctp_cmd_seq *")
and vnet_1843.getType().hasName("net *")
and vep_1844.getParentScope+() = func
and vasoc_1845.getParentScope+() = func
and vchunk_1846.getParentScope+() = func
and vcommands_1847.getParentScope+() = func
and vnet_1843.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
