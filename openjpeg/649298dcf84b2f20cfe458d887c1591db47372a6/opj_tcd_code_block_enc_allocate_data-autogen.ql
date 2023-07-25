/**
 * @name openjpeg-649298dcf84b2f20cfe458d887c1591db47372a6-opj_tcd_code_block_enc_allocate_data
 * @id cpp/openjpeg/649298dcf84b2f20cfe458d887c1591db47372a6/opj-tcd-code-block-enc-allocate-data
 * @description openjpeg-649298dcf84b2f20cfe458d887c1591db47372a6-src/lib/openjp2/tcd.c-opj_tcd_code_block_enc_allocate_data CVE-2020-27814
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="28"
		and not target_0.getValue()="63"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="x1"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="x0"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getParent().(AddExpr).getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
