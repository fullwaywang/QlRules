/**
 * @name linux-f3554aeb991214cbfafd17d55e2bfddb50282e32-set_geometry
 * @id cpp/linux/f3554aeb991214cbfafd17d55e2bfddb50282e32/set_geometry
 * @description linux-f3554aeb991214cbfafd17d55e2bfddb50282e32-set_geometry 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vg_3227) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sect"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3227
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rate"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3227
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="56"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(RemExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vg_3227) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="sect"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3227
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="head"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vg_3227
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Parameter vg_3227
where
not func_0(vg_3227)
and func_1(vg_3227)
and vg_3227.getType().hasName("floppy_struct *")
and vg_3227.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
