/**
 * @name openjpeg-397f62c0a838e15d667ef50e27d5d011d2c79c04-opj_tcd_code_block_enc_allocate_data
 * @id cpp/openjpeg/397f62c0a838e15d667ef50e27d5d011d2c79c04/opj-tcd-code-block-enc-allocate-data
 * @description openjpeg-397f62c0a838e15d667ef50e27d5d011d2c79c04-src/lib/openjp2/tcd.c-opj_tcd_code_block_enc_allocate_data CVE-2016-10504
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getAnOperand() instanceof MulExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vp_code_block_1181, MulExpr target_1) {
		target_1.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="x1"
		and target_1.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_code_block_1181
		and target_1.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="x0"
		and target_1.getLeftOperand().(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_code_block_1181
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_code_block_1181
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_code_block_1181
		and target_1.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

from Function func, Parameter vp_code_block_1181, MulExpr target_1
where
not func_0(func)
and func_1(vp_code_block_1181, target_1)
and vp_code_block_1181.getType().hasName("opj_tcd_cblk_enc_t *")
and vp_code_block_1181.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
