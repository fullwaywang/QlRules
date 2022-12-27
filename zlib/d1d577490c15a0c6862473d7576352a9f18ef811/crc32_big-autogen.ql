/**
 * @name zlib-d1d577490c15a0c6862473d7576352a9f18ef811-crc32_big
 * @id cpp/zlib/d1d577490c15a0c6862473d7576352a9f18ef811/crc32-big
 * @description zlib-d1d577490c15a0c6862473d7576352a9f18ef811-crc32_big CVE-2016-9843
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_8(Variable vbuf4_293) {
	exists(PostfixIncrExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vbuf4_293)
}

predicate func_17(Variable vbuf4_293) {
	exists(PostfixDecrExpr target_17 |
		target_17.getOperand().(VariableAccess).getTarget()=vbuf4_293)
}

predicate func_18(Variable vbuf4_293) {
	exists(PrefixIncrExpr target_18 |
		target_18.getOperand().(VariableAccess).getTarget()=vbuf4_293)
}

predicate func_26(Variable vc_292, Variable vbuf4_293) {
	exists(ExprStmt target_26 |
		target_26.getExpr().(AssignXorExpr).getLValue().(VariableAccess).getTarget()=vc_292
		and target_26.getExpr().(AssignXorExpr).getRValue().(PointerDereferenceExpr).getOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf4_293)
}

predicate func_28(Function func) {
	exists(ExprStmt target_28 |
		target_28.getExpr() instanceof PostfixIncrExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28)
}

from Function func, Variable vc_292, Variable vbuf4_293
where
func_8(vbuf4_293)
and func_17(vbuf4_293)
and func_18(vbuf4_293)
and func_26(vc_292, vbuf4_293)
and func_28(func)
and vc_292.getType().hasName("z_crc_t")
and vbuf4_293.getType().hasName("const z_crc_t *")
and vc_292.getParentScope+() = func
and vbuf4_293.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
