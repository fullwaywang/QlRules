/**
 * @name ghostscript-bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39-bjc_compress
 * @id cpp/ghostscript/bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39/bjc-compress
 * @description ghostscript-bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39-contrib/gdevbjca.c-bjc_compress CVE-2020-16297
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vexam_331, PrefixIncrExpr target_0) {
		target_0.getOperand().(VariableAccess).getTarget()=vexam_331
}

predicate func_1(Variable vexam_331, VariableAccess target_1) {
		target_1.getTarget()=vexam_331
		and target_1.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("const byte *")
}

from Function func, Variable vexam_331, PrefixIncrExpr target_0, VariableAccess target_1
where
func_0(vexam_331, target_0)
and func_1(vexam_331, target_1)
and vexam_331.getType().hasName("const byte *")
and vexam_331.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
