/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_asconf_ack
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-asconf-ack
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_asconf_ack CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vep_3972, Parameter vasoc_3973, Parameter vtype_3974, Parameter varg_3975, Parameter vcommands_3976, Parameter vnet_3971) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_discard_chunk")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_3971
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_3972
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_3973
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_3974
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_3975
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_3976)
}

from Function func, Parameter vep_3972, Parameter vasoc_3973, Parameter vtype_3974, Parameter varg_3975, Parameter vcommands_3976, Parameter vnet_3971
where
func_0(vep_3972, vasoc_3973, vtype_3974, varg_3975, vcommands_3976, vnet_3971)
and vep_3972.getType().hasName("const sctp_endpoint *")
and vasoc_3973.getType().hasName("const sctp_association *")
and vtype_3974.getType().hasName("const sctp_subtype")
and varg_3975.getType().hasName("void *")
and vcommands_3976.getType().hasName("sctp_cmd_seq *")
and vnet_3971.getType().hasName("net *")
and vep_3972.getParentScope+() = func
and vasoc_3973.getParentScope+() = func
and vtype_3974.getParentScope+() = func
and varg_3975.getParentScope+() = func
and vcommands_3976.getParentScope+() = func
and vnet_3971.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
