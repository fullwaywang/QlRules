/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-bitmap_cache_new
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/bitmap-cache-new
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/cache/bitmap.c-bitmap_cache_new CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbitmapCache_275, NotExpr target_2, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="maxCells"
		and target_0.getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Variable vbitmapCache_275, NotExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="cells"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbitmapCache_275
}

from Function func, Variable vbitmapCache_275, PointerFieldAccess target_0, NotExpr target_2
where
func_0(vbitmapCache_275, target_2, target_0)
and func_2(vbitmapCache_275, target_2)
and vbitmapCache_275.getType().hasName("rdpBitmapCache *")
and vbitmapCache_275.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
