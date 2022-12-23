/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_unexpected_init
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-unexpected-init
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_unexpected_init CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vep_1497, Parameter vasoc_1498, Parameter vtype_1499, Parameter varg_1500, Parameter vcommands_1501, Parameter vnet_1496) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_violation_chunklen")
		and not target_0.getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_1496
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_1497
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_1498
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_1499
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_1500
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_1501)
}

from Function func, Parameter vep_1497, Parameter vasoc_1498, Parameter vtype_1499, Parameter varg_1500, Parameter vcommands_1501, Parameter vnet_1496
where
func_0(vep_1497, vasoc_1498, vtype_1499, varg_1500, vcommands_1501, vnet_1496)
and vep_1497.getType().hasName("const sctp_endpoint *")
and vasoc_1498.getType().hasName("const sctp_association *")
and vtype_1499.getType().hasName("const sctp_subtype")
and varg_1500.getType().hasName("void *")
and vcommands_1501.getType().hasName("sctp_cmd_seq *")
and vnet_1496.getType().hasName("net *")
and vep_1497.getParentScope+() = func
and vasoc_1498.getParentScope+() = func
and vtype_1499.getParentScope+() = func
and varg_1500.getParentScope+() = func
and vcommands_1501.getParentScope+() = func
and vnet_1496.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
