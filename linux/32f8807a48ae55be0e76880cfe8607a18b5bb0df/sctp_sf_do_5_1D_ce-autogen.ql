/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_5_1D_ce
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-5-1D-ce
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_5_1D_ce CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vep_692, Parameter vasoc_693, Parameter vtype_694, Parameter varg_695, Parameter vcommands_696, Parameter vnet_691) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sctp_sf_pdiscard")
		and not target_0.getTarget().hasName("sctp_sf_violation_chunklen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnet_691
		and target_0.getArgument(1).(VariableAccess).getTarget()=vep_692
		and target_0.getArgument(2).(VariableAccess).getTarget()=vasoc_693
		and target_0.getArgument(3).(VariableAccess).getTarget()=vtype_694
		and target_0.getArgument(4).(VariableAccess).getTarget()=varg_695
		and target_0.getArgument(5).(VariableAccess).getTarget()=vcommands_696)
}

predicate func_1(Parameter vep_692, Parameter vasoc_693, Parameter vtype_694, Parameter varg_695, Parameter vcommands_696, Variable vchunk_701, Parameter vnet_691, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vasoc_693
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_701
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_693
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("sctp_sf_pdiscard")
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_691
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_692
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_693
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_694
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_695
		and target_1.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_696
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vep_692, Parameter vasoc_693, Parameter vtype_694, Parameter varg_695, Parameter vcommands_696, Variable vchunk_701, Parameter vnet_691) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("sctp_sf_violation_chunklen")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_691
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_692
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_693
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_694
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_695
		and target_2.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_696
		and target_2.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_chunk_length_valid")
		and target_2.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_701
		and target_2.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4")
}

predicate func_3(Parameter vep_692, Parameter vasoc_693, Parameter vtype_694, Parameter varg_695, Parameter vcommands_696, Parameter vnet_691) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("sctp_sf_tabort_8_4_8")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vnet_691
		and target_3.getArgument(1).(VariableAccess).getTarget()=vep_692
		and target_3.getArgument(2).(VariableAccess).getTarget()=vasoc_693
		and target_3.getArgument(3).(VariableAccess).getTarget()=vtype_694
		and target_3.getArgument(4).(VariableAccess).getTarget()=varg_695
		and target_3.getArgument(5).(VariableAccess).getTarget()=vcommands_696)
}

from Function func, Parameter vep_692, Parameter vasoc_693, Parameter vtype_694, Parameter varg_695, Parameter vcommands_696, Variable vchunk_701, Parameter vnet_691
where
func_0(vep_692, vasoc_693, vtype_694, varg_695, vcommands_696, vnet_691)
and not func_1(vep_692, vasoc_693, vtype_694, varg_695, vcommands_696, vchunk_701, vnet_691, func)
and not func_2(vep_692, vasoc_693, vtype_694, varg_695, vcommands_696, vchunk_701, vnet_691)
and vep_692.getType().hasName("const sctp_endpoint *")
and func_3(vep_692, vasoc_693, vtype_694, varg_695, vcommands_696, vnet_691)
and vasoc_693.getType().hasName("const sctp_association *")
and vtype_694.getType().hasName("const sctp_subtype")
and varg_695.getType().hasName("void *")
and vcommands_696.getType().hasName("sctp_cmd_seq *")
and vchunk_701.getType().hasName("sctp_chunk *")
and vnet_691.getType().hasName("net *")
and vep_692.getParentScope+() = func
and vasoc_693.getParentScope+() = func
and vtype_694.getParentScope+() = func
and varg_695.getParentScope+() = func
and vcommands_696.getParentScope+() = func
and vchunk_701.getParentScope+() = func
and vnet_691.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
