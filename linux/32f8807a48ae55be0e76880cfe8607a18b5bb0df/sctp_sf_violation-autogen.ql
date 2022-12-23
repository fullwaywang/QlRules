/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_violation
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-violation
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_violation CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcommands_4641, Variable vchunk_4643, Parameter vnet_4636, Parameter vep_4637, Parameter vasoc_4638, Parameter vtype_4639, Parameter varg_4640, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_4643
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_4638
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_4636
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_4637
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_4638
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_4639
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_4640
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_4641
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter varg_4640) {
	exists(Initializer target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=varg_4640)
}

from Function func, Parameter vcommands_4641, Variable vchunk_4643, Parameter vnet_4636, Parameter vep_4637, Parameter vasoc_4638, Parameter vtype_4639, Parameter varg_4640
where
not func_0(vcommands_4641, vchunk_4643, vnet_4636, vep_4637, vasoc_4638, vtype_4639, varg_4640, func)
and vcommands_4641.getType().hasName("sctp_cmd_seq *")
and vchunk_4643.getType().hasName("sctp_chunk *")
and vnet_4636.getType().hasName("net *")
and vep_4637.getType().hasName("const sctp_endpoint *")
and vasoc_4638.getType().hasName("const sctp_association *")
and vtype_4639.getType().hasName("const sctp_subtype")
and varg_4640.getType().hasName("void *")
and func_1(varg_4640)
and vcommands_4641.getParentScope+() = func
and vchunk_4643.getParentScope+() = func
and vnet_4636.getParentScope+() = func
and vep_4637.getParentScope+() = func
and vasoc_4638.getParentScope+() = func
and vtype_4639.getParentScope+() = func
and varg_4640.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
