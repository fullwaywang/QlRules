/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-fill_grant_buffer
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/fill-grant-buffer
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-fill_grant_buffer CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_303) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="feature_persistent"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinfo_303)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1161"
		and not target_2.getValue()="1163"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(BitwiseOrExpr target_3 |
		target_3.getValue()="3328"
		and target_3.getLeftOperand() instanceof BitwiseOrExpr
		and target_3.getRightOperand().(Literal).getValue()="256"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(BitwiseOrExpr target_4 |
		target_4.getValue()="3072"
		and target_4.getLeftOperand().(Literal).getValue()="1024"
		and target_4.getRightOperand().(Literal).getValue()="2048"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

from Function func, Variable vinfo_303
where
func_0(vinfo_303)
and func_2(func)
and not func_3(func)
and func_4(func)
and vinfo_303.getType().hasName("blkfront_info *")
and vinfo_303.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
