/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_5_2_4_dupcook
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-do-5-2-4-dupcook
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_do_5_2_4_dupcook CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vasoc_2188, Variable vchunk_2194) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_2194
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_2188
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vasoc_2188
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_chunk_length_valid")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_2194
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4")
}

predicate func_1(Parameter vnet_2186, Parameter vep_2187, Parameter vasoc_2188, Parameter vtype_2189, Parameter varg_2190, Parameter vcommands_2191, Variable vchunk_2194) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sctp_sf_violation_chunklen")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnet_2186
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_2187
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vasoc_2188
		and target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_2189
		and target_1.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=varg_2190
		and target_1.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcommands_2191
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_chunk_length_valid")
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_2194
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4")
}

predicate func_2(Parameter vnet_2186, Parameter vep_2187, Parameter vasoc_2188, Parameter vtype_2189, Parameter varg_2190, Parameter vcommands_2191) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sctp_sf_violation_chunklen")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vnet_2186
		and target_2.getArgument(1).(VariableAccess).getTarget()=vep_2187
		and target_2.getArgument(2).(VariableAccess).getTarget()=vasoc_2188
		and target_2.getArgument(3).(VariableAccess).getTarget()=vtype_2189
		and target_2.getArgument(4).(VariableAccess).getTarget()=varg_2190
		and target_2.getArgument(5).(VariableAccess).getTarget()=vcommands_2191)
}

predicate func_3(Variable vchunk_2194) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("sctp_chunk_length_valid")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vchunk_2194
		and target_3.getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getArgument(1).(SizeofTypeOperator).getValue()="4")
}

from Function func, Parameter vnet_2186, Parameter vep_2187, Parameter vasoc_2188, Parameter vtype_2189, Parameter varg_2190, Parameter vcommands_2191, Variable vchunk_2194
where
not func_0(vasoc_2188, vchunk_2194)
and func_1(vnet_2186, vep_2187, vasoc_2188, vtype_2189, varg_2190, vcommands_2191, vchunk_2194)
and vnet_2186.getType().hasName("net *")
and vep_2187.getType().hasName("const sctp_endpoint *")
and vasoc_2188.getType().hasName("const sctp_association *")
and func_2(vnet_2186, vep_2187, vasoc_2188, vtype_2189, varg_2190, vcommands_2191)
and vtype_2189.getType().hasName("const sctp_subtype")
and varg_2190.getType().hasName("void *")
and vcommands_2191.getType().hasName("sctp_cmd_seq *")
and vchunk_2194.getType().hasName("sctp_chunk *")
and func_3(vchunk_2194)
and vnet_2186.getParentScope+() = func
and vep_2187.getParentScope+() = func
and vasoc_2188.getParentScope+() = func
and vtype_2189.getParentScope+() = func
and varg_2190.getParentScope+() = func
and vcommands_2191.getParentScope+() = func
and vchunk_2194.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
