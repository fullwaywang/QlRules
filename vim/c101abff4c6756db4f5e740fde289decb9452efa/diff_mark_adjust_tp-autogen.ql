/**
 * @name vim-c101abff4c6756db4f5e740fde289decb9452efa-diff_mark_adjust_tp
 * @id cpp/vim/c101abff4c6756db4f5e740fde289decb9452efa/diff-mark-adjust-tp
 * @description vim-c101abff4c6756db4f5e740fde289decb9452efa-src/diff.c-diff_mark_adjust_tp CVE-2022-2210
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voff_304, Variable vlnum_deleted_306, Variable vdp_299, Parameter vidx_293, RelationalOperation target_2, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_304
		and target_0.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_lnum"
		and target_0.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
		and target_0.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_293
		and target_0.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlnum_deleted_306
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Variable voff_304, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_304
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vdp_299, Parameter vidx_293, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="df_lnum"
		and target_2.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_299
		and target_2.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_293
}

from Function func, Variable voff_304, Variable vlnum_deleted_306, Variable vdp_299, Parameter vidx_293, ExprStmt target_0, ExprStmt target_1, RelationalOperation target_2
where
func_0(voff_304, vlnum_deleted_306, vdp_299, vidx_293, target_2, target_0)
and func_1(voff_304, target_2, target_1)
and func_2(vdp_299, vidx_293, target_2)
and voff_304.getType().hasName("int")
and vlnum_deleted_306.getType().hasName("linenr_T")
and vdp_299.getType().hasName("diff_T *")
and vidx_293.getType().hasName("int")
and voff_304.getParentScope+() = func
and vlnum_deleted_306.getParentScope+() = func
and vdp_299.getParentScope+() = func
and vidx_293.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
