/**
 * @name linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_ootb
 * @id cpp/linux/32f8807a48ae55be0e76880cfe8607a18b5bb0df/sctp-sf-ootb
 * @description linux-32f8807a48ae55be0e76880cfe8607a18b5bb0df-sctp_sf_ootb CVE-2021-3772
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vasoc_3651, Variable vchunk_3655, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vasoc_3651
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sctp_vtag_verify")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchunk_3655
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vasoc_3651
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vasoc_3651
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vep_3650, Parameter vasoc_3651, Parameter vtype_3652, Parameter varg_3653, Parameter vcommands_3653, Parameter vnet_3649) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sctp_sf_violation_chunklen")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vnet_3649
		and target_1.getArgument(1).(VariableAccess).getTarget()=vep_3650
		and target_1.getArgument(2).(VariableAccess).getTarget()=vasoc_3651
		and target_1.getArgument(3).(VariableAccess).getTarget()=vtype_3652
		and target_1.getArgument(4).(VariableAccess).getTarget()=varg_3653
		and target_1.getArgument(5).(VariableAccess).getTarget()=vcommands_3653)
}

predicate func_2(Variable vchunk_3655) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="skb"
		and target_2.getQualifier().(VariableAccess).getTarget()=vchunk_3655)
}

from Function func, Parameter vep_3650, Parameter vasoc_3651, Parameter vtype_3652, Parameter varg_3653, Parameter vcommands_3653, Parameter vnet_3649, Variable vchunk_3655
where
not func_0(vasoc_3651, vchunk_3655, func)
and vasoc_3651.getType().hasName("const sctp_association *")
and func_1(vep_3650, vasoc_3651, vtype_3652, varg_3653, vcommands_3653, vnet_3649)
and vtype_3652.getType().hasName("const sctp_subtype")
and varg_3653.getType().hasName("void *")
and vcommands_3653.getType().hasName("sctp_cmd_seq *")
and vnet_3649.getType().hasName("net *")
and vchunk_3655.getType().hasName("sctp_chunk *")
and func_2(vchunk_3655)
and vep_3650.getParentScope+() = func
and vasoc_3651.getParentScope+() = func
and vtype_3652.getParentScope+() = func
and varg_3653.getParentScope+() = func
and vcommands_3653.getParentScope+() = func
and vnet_3649.getParentScope+() = func
and vchunk_3655.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
