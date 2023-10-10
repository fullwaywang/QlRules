/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_discard_chunk
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-discard-chunk
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_discard_chunk CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vep_4570, Parameter vasoc_4571, Parameter vtype_4572, Parameter varg_4573, Parameter vcommands_4574, Variable vchunk_4576, Parameter vnet_4569, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vasoc_4571
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_4576
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_4571
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_4569
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_4570
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_4571
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_4572
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_4573
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_4574
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter varg_4573) {
	exists(Initializer target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=varg_4573)
}

from Function func, Parameter vep_4570, Parameter vasoc_4571, Parameter vtype_4572, Parameter varg_4573, Parameter vcommands_4574, Variable vchunk_4576, Parameter vnet_4569
where
not func_0(vep_4570, vasoc_4571, vtype_4572, varg_4573, vcommands_4574, vchunk_4576, vnet_4569, func)
and vep_4570.getType().hasName("const sctp_endpoint *")
and vasoc_4571.getType().hasName("const sctp_association *")
and vtype_4572.getType().hasName("const sctp_subtype")
and varg_4573.getType().hasName("void *")
and func_1(varg_4573)
and vcommands_4574.getType().hasName("sctp_cmd_seq *")
and vchunk_4576.getType().hasName("sctp_chunk *")
and vnet_4569.getType().hasName("net *")
and vep_4570.getParentScope+() = func
and vasoc_4571.getParentScope+() = func
and vtype_4572.getParentScope+() = func
and varg_4573.getParentScope+() = func
and vcommands_4574.getParentScope+() = func
and vchunk_4576.getParentScope+() = func
and vnet_4569.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
