/**
 * @name ffmpeg-0749082eb93ea02fa4b770da86597450cec84054-config_input
 * @id cpp/ffmpeg/0749082eb93ea02fa4b770da86597450cec84054/config-input
 * @description ffmpeg-0749082eb93ea02fa4b770da86597450cec84054-libavfilter/vf_bm3d.c-config_input CVE-2020-22035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_780, AddressOfExpr target_8) {
	exists(BitwiseAndExpr target_0 |
		target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof ArrayExpr
		and target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_0.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_0.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_0.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_8.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_780) {
	exists(BitwiseAndExpr target_1 |
		target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof ArrayExpr
		and target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_1.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_1.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_1.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_1.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_2(Variable vs_780) {
	exists(BitwiseAndExpr target_2 |
		target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof ArrayExpr
		and target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_2.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_2.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_3(Variable vs_780) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof ArrayExpr
		and target_3.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_3.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_3.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="block_size"
		and target_3.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_3.getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_4(Variable vs_780, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="planewidth"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_4.getArrayOffset().(Literal).getValue()="0"
}

predicate func_5(Variable vs_780, ArrayExpr target_5) {
		target_5.getArrayBase().(PointerFieldAccess).getTarget().getName()="planeheight"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_5.getArrayOffset().(Literal).getValue()="0"
}

predicate func_6(Variable vs_780, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="planewidth"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_6.getArrayOffset().(Literal).getValue()="0"
}

predicate func_7(Variable vs_780, ArrayExpr target_7) {
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="planeheight"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
		and target_7.getArrayOffset().(Literal).getValue()="0"
}

predicate func_8(Variable vs_780, AddressOfExpr target_8) {
		target_8.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="slices"
		and target_8.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_780
}

from Function func, Variable vs_780, ArrayExpr target_4, ArrayExpr target_5, ArrayExpr target_6, ArrayExpr target_7, AddressOfExpr target_8
where
not func_0(vs_780, target_8)
and not func_1(vs_780)
and not func_2(vs_780)
and not func_3(vs_780)
and func_4(vs_780, target_4)
and func_5(vs_780, target_5)
and func_6(vs_780, target_6)
and func_7(vs_780, target_7)
and func_8(vs_780, target_8)
and vs_780.getType().hasName("BM3DContext *")
and vs_780.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
