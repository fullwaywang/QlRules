/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shutdown_sent_abort
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-shutdown-sent-abort
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shutdown_sent_abort CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2358, Parameter vep_2359, Parameter vasoc_2360, Parameter vtype_2361, Parameter varg_2362, Parameter vcommands_2363) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_discard_chunk")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_2358
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_2359
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_2360
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_2361
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_2362
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_2363)
}

from Function func, Parameter vnet_2358, Parameter vep_2359, Parameter vasoc_2360, Parameter vtype_2361, Parameter varg_2362, Parameter vcommands_2363
where
func_0(vnet_2358, vep_2359, vasoc_2360, vtype_2361, varg_2362, vcommands_2363)
and vnet_2358.getType().hasName("net *")
and vep_2359.getType().hasName("const sctp_endpoint *")
and vasoc_2360.getType().hasName("const sctp_association *")
and vtype_2361.getType().hasName("const sctp_subtype")
and varg_2362.getType().hasName("void *")
and vcommands_2363.getType().hasName("sctp_cmd_seq *")
and vnet_2358.getParentScope+() = func
and vep_2359.getParentScope+() = func
and vasoc_2360.getParentScope+() = func
and vtype_2361.getParentScope+() = func
and varg_2362.getParentScope+() = func
and vcommands_2363.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
