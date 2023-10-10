/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_asconf
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-asconf
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_asconf CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_3829, Parameter vep_3830, Parameter vasoc_3831, Parameter vtype_3832, Parameter varg_3833, Parameter vcommands_3834) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_discard_chunk")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_3829
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_3830
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_3831
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_3832
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_3833
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_3834)
}

from Function func, Parameter vnet_3829, Parameter vep_3830, Parameter vasoc_3831, Parameter vtype_3832, Parameter varg_3833, Parameter vcommands_3834
where
func_0(vnet_3829, vep_3830, vasoc_3831, vtype_3832, varg_3833, vcommands_3834)
and vnet_3829.getType().hasName("net *")
and vep_3830.getType().hasName("const sctp_endpoint *")
and vasoc_3831.getType().hasName("const sctp_association *")
and vtype_3832.getType().hasName("const sctp_subtype")
and varg_3833.getType().hasName("void *")
and vcommands_3834.getType().hasName("sctp_cmd_seq *")
and vnet_3829.getParentScope+() = func
and vep_3830.getParentScope+() = func
and vasoc_3831.getParentScope+() = func
and vtype_3832.getParentScope+() = func
and varg_3833.getParentScope+() = func
and vcommands_3834.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
