/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shut_8_4_5
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-shut-8-4-5
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_shut_8_4_5 CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtype_3745, Parameter varg_3746, Parameter vcommands_3747, Parameter vnet_3742, Parameter vep_3743, Parameter vasoc_3744) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sctp_sf_pdiscard")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_3742
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_3743
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_3744
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_3745
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_3746
		and target_0.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_3747
		and target_0.getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_1(Variable vchunk_3750, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_chunk_length_valid")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_3750
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
		and target_1.getThen() instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vtype_3745, Parameter varg_3746, Parameter vcommands_3747, Variable vchunk_3750, Parameter vnet_3742, Parameter vep_3743, Parameter vasoc_3744
where
func_0(vtype_3745, varg_3746, vcommands_3747, vnet_3742, vep_3743, vasoc_3744)
and func_1(vchunk_3750, func)
and vtype_3745.getType().hasName("const sctp_subtype")
and varg_3746.getType().hasName("void *")
and vcommands_3747.getType().hasName("sctp_cmd_seq *")
and vchunk_3750.getType().hasName("sctp_chunk *")
and vnet_3742.getType().hasName("net *")
and vep_3743.getType().hasName("const sctp_endpoint *")
and vasoc_3744.getType().hasName("const sctp_association *")
and vtype_3745.getParentScope+() = func
and varg_3746.getParentScope+() = func
and vcommands_3747.getParentScope+() = func
and vchunk_3750.getParentScope+() = func
and vnet_3742.getParentScope+() = func
and vep_3743.getParentScope+() = func
and vasoc_3744.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
