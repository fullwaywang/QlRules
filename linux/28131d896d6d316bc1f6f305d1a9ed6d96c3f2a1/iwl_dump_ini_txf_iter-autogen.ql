/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_ini_txf_iter
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dump-ini-txf-iter
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_ini_txf_iter CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_1283, Variable viter_1289, Variable vreg_dump_1290, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1283
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1283
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1283
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1283
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vreg_dump_1290
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="fifo_size"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1289
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vfwrt_1283) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="trans"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfwrt_1283)
}

predicate func_2(Variable viter_1289) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="fifo_size"
		and target_2.getQualifier().(VariableAccess).getTarget()=viter_1289)
}

predicate func_3(Variable vreg_dump_1290, Variable vdata_1294) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vdata_1294
		and target_3.getRValue().(VariableAccess).getTarget()=vreg_dump_1290)
}

from Function func, Parameter vfwrt_1283, Variable viter_1289, Variable vreg_dump_1290, Variable vdata_1294
where
not func_0(vfwrt_1283, viter_1289, vreg_dump_1290, func)
and vfwrt_1283.getType().hasName("iwl_fw_runtime *")
and func_1(vfwrt_1283)
and viter_1289.getType().hasName("iwl_txf_iter_data *")
and func_2(viter_1289)
and vreg_dump_1290.getType().hasName("iwl_fw_ini_error_dump_register *")
and func_3(vreg_dump_1290, vdata_1294)
and vdata_1294.getType().hasName("__le32 *")
and vfwrt_1283.getParentScope+() = func
and viter_1289.getParentScope+() = func
and vreg_dump_1290.getParentScope+() = func
and vdata_1294.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
