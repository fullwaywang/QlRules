/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkfront_setup_indirect
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/blkfront-setup-indirect
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-blkfront_setup_indirect CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_2151) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="feature_persistent"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinfo_2151)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1203"
		and not target_1.getValue()="1205"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(BitwiseOrExpr target_2 |
		target_2.getValue()="3520"
		and target_2.getLeftOperand() instanceof BitwiseOrExpr
		and target_2.getRightOperand().(Literal).getValue()="256"
		and target_2.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_2.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(BitwiseOrExpr target_3 |
		target_3.getValue()="3264"
		and target_3.getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_3.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3072"
		and target_3.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_3.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_3.getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getRightOperand().(Literal).getValue()="128"
		and target_3.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_3.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

from Function func, Variable vinfo_2151
where
func_0(vinfo_2151)
and func_1(func)
and not func_2(func)
and func_3(func)
and vinfo_2151.getType().hasName("blkfront_info *")
and vinfo_2151.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
