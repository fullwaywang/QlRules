/**
 * @name ffmpeg-5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd-get_tilt_comp
 * @id cpp/ffmpeg/5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd/get-tilt-comp
 * @description ffmpeg-5f0acc5064ed501cb40d4aaccae2b3ce5c4552fd-libavcodec/g729postfilter.c-get_tilt_comp CVE-2020-20902
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrh1_431, LogicalOrExpr target_4) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vrh1_431
		and target_0.getRightOperand().(BinaryBitwiseOperation).getValue()="32768"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrh1_431, VariableAccess target_1) {
		target_1.getTarget()=vrh1_431
}

predicate func_3(Variable vrh1_431, BinaryBitwiseOperation target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vrh1_431
		and target_3.getRightOperand() instanceof Literal
}

predicate func_4(Variable vrh1_431, LogicalOrExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrh1_431
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vrh1_431
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ConditionalExpr).getElse().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vrh1_431
}

from Function func, Variable vrh1_431, VariableAccess target_1, BinaryBitwiseOperation target_3, LogicalOrExpr target_4
where
not func_0(vrh1_431, target_4)
and func_1(vrh1_431, target_1)
and func_3(vrh1_431, target_3)
and func_4(vrh1_431, target_4)
and vrh1_431.getType().hasName("int")
and vrh1_431.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
