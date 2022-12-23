/**
 * @name linux-54a20552e1eae07aa240fa370a0293e006b5faed-update_exception_bitmap
 * @id cpp/linux/54a20552e1eae07aa240fa370a0293e006b5faed/update_exception_bitmap
 * @description linux-54a20552e1eae07aa240fa370a0293e006b5faed-update_exception_bitmap CVE-2015-5307
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable veb_1639) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="409794"
		and target_0.getLeftOperand() instanceof BitwiseOrExpr
		and target_0.getRightOperand().(BinaryBitwiseOperation).getValue()="131072"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="17"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=veb_1639)
}

predicate func_1(Variable veb_1639) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="278722"
		and target_1.getLeftOperand().(BitwiseOrExpr).getValue()="278720"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="278592"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="16448"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="262144"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="18"
		and target_1.getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_1.getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
		and target_1.getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_1.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=veb_1639)
}

from Function func, Variable veb_1639
where
not func_0(veb_1639)
and func_1(veb_1639)
and veb_1639.getType().hasName("u32")
and veb_1639.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
