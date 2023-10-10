/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_8_5_1_E_sa
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-8-5-1-E-sa
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_8_5_1_E_sa CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vasoc_3806, Variable vchunk_3811, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_3811
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_3806
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vasoc_3806
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vasoc_3806, Parameter vtype_3807, Parameter varg_3808, Parameter vcommands_3809, Parameter vep_3805, Parameter vnet_3804) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sctp_sf_violation_chunklen")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vnet_3804
		and target_1.getArgument(1).(VariableAccess).getTarget()=vep_3805
		and target_1.getArgument(2).(VariableAccess).getTarget()=vasoc_3806
		and target_1.getArgument(3).(VariableAccess).getTarget()=vtype_3807
		and target_1.getArgument(4).(VariableAccess).getTarget()=varg_3808
		and target_1.getArgument(5).(VariableAccess).getTarget()=vcommands_3809)
}

from Function func, Parameter vasoc_3806, Parameter vtype_3807, Parameter varg_3808, Parameter vcommands_3809, Variable vchunk_3811, Parameter vep_3805, Parameter vnet_3804
where
not func_0(vasoc_3806, vchunk_3811, func)
and vasoc_3806.getType().hasName("const sctp_association *")
and func_1(vasoc_3806, vtype_3807, varg_3808, vcommands_3809, vep_3805, vnet_3804)
and vtype_3807.getType().hasName("const sctp_subtype")
and varg_3808.getType().hasName("void *")
and vcommands_3809.getType().hasName("sctp_cmd_seq *")
and vchunk_3811.getType().hasName("sctp_chunk *")
and vep_3805.getType().hasName("const sctp_endpoint *")
and vnet_3804.getType().hasName("net *")
and vasoc_3806.getParentScope+() = func
and vtype_3807.getParentScope+() = func
and varg_3808.getParentScope+() = func
and vcommands_3809.getParentScope+() = func
and vchunk_3811.getParentScope+() = func
and vep_3805.getParentScope+() = func
and vnet_3804.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
