/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_dbg_read_d3_debug_data
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fw-dbg-read-d3-debug-data
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_dbg_read_d3_debug_data CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vfwrt_2770, Variable vcfg_2772, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_2770
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_2770
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_2770
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_2770
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="d3_debug_data_base_addr"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_2772
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="d3_debug_data"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dump"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_2770
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="d3_debug_data_length"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcfg_2772
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vfwrt_2770) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="dump"
		and target_3.getQualifier().(VariableAccess).getTarget()=vfwrt_2770)
}

predicate func_4(Variable vcfg_2772) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="d3_debug_data_length"
		and target_4.getQualifier().(VariableAccess).getTarget()=vcfg_2772)
}

from Function func, Parameter vfwrt_2770, Variable vcfg_2772
where
not func_1(vfwrt_2770, vcfg_2772, func)
and vfwrt_2770.getType().hasName("iwl_fw_runtime *")
and func_3(vfwrt_2770)
and vcfg_2772.getType().hasName("const iwl_cfg *")
and func_4(vcfg_2772)
and vfwrt_2770.getParentScope+() = func
and vcfg_2772.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
