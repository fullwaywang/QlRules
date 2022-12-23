/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_ini_dev_mem_iter
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dump-ini-dev-mem-iter
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_ini_dev_mem_iter CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_1135, Variable vreg_1139, Variable vrange_1140, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreg_1139
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65535"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="15"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1135
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1135
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1135
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1135
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrange_1140
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="dev_addr"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreg_1139
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vfwrt_1135) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="trans"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfwrt_1135)
}

predicate func_2(Variable vreg_1139) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(VariableAccess).getTarget()=vreg_1139)
}

predicate func_3(Variable vrange_1140) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="data"
		and target_3.getQualifier().(VariableAccess).getTarget()=vrange_1140)
}

from Function func, Parameter vfwrt_1135, Variable vreg_1139, Variable vrange_1140
where
not func_0(vfwrt_1135, vreg_1139, vrange_1140, func)
and vfwrt_1135.getType().hasName("iwl_fw_runtime *")
and func_1(vfwrt_1135)
and vreg_1139.getType().hasName("iwl_fw_ini_region_tlv *")
and func_2(vreg_1139)
and vrange_1140.getType().hasName("iwl_fw_ini_error_dump_range *")
and func_3(vrange_1140)
and vfwrt_1135.getParentScope+() = func
and vreg_1139.getParentScope+() = func
and vrange_1140.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
