/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_runtime_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fw-runtime-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_runtime_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_16) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="2792"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfwrt_16)
}

predicate func_1(Parameter vfwrt_16, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_16
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("const iwl_dump_sanitize_ops *")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vfwrt_16, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_16
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vfwrt_16) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="ops"
		and target_3.getQualifier().(VariableAccess).getTarget()=vfwrt_16)
}

from Function func, Parameter vfwrt_16
where
func_0(vfwrt_16)
and not func_1(vfwrt_16, func)
and not func_2(vfwrt_16, func)
and vfwrt_16.getType().hasName("iwl_fw_runtime *")
and func_3(vfwrt_16)
and vfwrt_16.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
