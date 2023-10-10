/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_9_1_abort
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-9-1-abort
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_9_1_abort CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2628, Parameter vep_2629, Parameter vasoc_2630, Parameter vtype_2631, Parameter varg_2632, Parameter vcommands_2633) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_discard_chunk")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_2628
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_2629
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_2630
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_2631
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_2632
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_2633)
}

from Function func, Parameter vnet_2628, Parameter vep_2629, Parameter vasoc_2630, Parameter vtype_2631, Parameter varg_2632, Parameter vcommands_2633
where
func_0(vnet_2628, vep_2629, vasoc_2630, vtype_2631, varg_2632, vcommands_2633)
and vnet_2628.getType().hasName("net *")
and vep_2629.getType().hasName("const sctp_endpoint *")
and vasoc_2630.getType().hasName("const sctp_association *")
and vtype_2631.getType().hasName("const sctp_subtype")
and varg_2632.getType().hasName("void *")
and vcommands_2633.getType().hasName("sctp_cmd_seq *")
and vnet_2628.getParentScope+() = func
and vep_2629.getParentScope+() = func
and vasoc_2630.getParentScope+() = func
and vtype_2631.getParentScope+() = func
and varg_2632.getParentScope+() = func
and vcommands_2633.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
