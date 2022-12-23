/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shutdown_pending_abort
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-shutdown-pending-abort
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shutdown_pending_abort CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2312, Parameter vep_2313, Parameter vasoc_2314, Parameter vtype_2315, Parameter varg_2316, Parameter vcommands_2317) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_discard_chunk")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_2312
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_2313
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_2314
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_2315
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_2316
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_2317)
}

from Function func, Parameter vnet_2312, Parameter vep_2313, Parameter vasoc_2314, Parameter vtype_2315, Parameter varg_2316, Parameter vcommands_2317
where
func_0(vnet_2312, vep_2313, vasoc_2314, vtype_2315, varg_2316, vcommands_2317)
and vnet_2312.getType().hasName("net *")
and vep_2313.getType().hasName("const sctp_endpoint *")
and vasoc_2314.getType().hasName("const sctp_association *")
and vtype_2315.getType().hasName("const sctp_subtype")
and varg_2316.getType().hasName("void *")
and vcommands_2317.getType().hasName("sctp_cmd_seq *")
and vnet_2312.getParentScope+() = func
and vep_2313.getParentScope+() = func
and vasoc_2314.getParentScope+() = func
and vtype_2315.getParentScope+() = func
and varg_2316.getParentScope+() = func
and vcommands_2317.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
