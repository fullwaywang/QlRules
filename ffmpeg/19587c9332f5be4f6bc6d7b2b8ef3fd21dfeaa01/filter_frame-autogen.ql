/**
 * @name ffmpeg-19587c9332f5be4f6bc6d7b2b8ef3fd21dfeaa01-filter_frame
 * @id cpp/ffmpeg/19587c9332f5be4f6bc6d7b2b8ef3fd21dfeaa01/filter-frame
 * @description ffmpeg-19587c9332f5be4f6bc6d7b2b8ef3fd21dfeaa01-libavfilter/vf_lenscorrection.c-filter_frame CVE-2020-20892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhdiv_158, VariableAccess target_0) {
		target_0.getTarget()=vhdiv_158
}

predicate func_1(Variable vvdiv_159, VariableAccess target_1) {
		target_1.getTarget()=vvdiv_159
}

predicate func_2(Variable vrect_144, Variable vhsub_156, DivExpr target_11, BinaryBitwiseOperation target_4) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("int")
		and target_2.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_2.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getType().hasName("int")
		and target_2.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_2.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof BinaryBitwiseOperation
		and target_2.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getElse().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vhsub_156
		and target_2.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getElse().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vrect_144, Variable vvsub_157, DivExpr target_13, BinaryBitwiseOperation target_5) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvsub_157
		and target_3.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_3.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vvsub_157
		and target_3.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_3.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof BinaryBitwiseOperation
		and target_3.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getElse().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vvsub_157
		and target_3.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getRightOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vhsub_156, BinaryBitwiseOperation target_4) {
		target_4.getLeftOperand().(Literal).getValue()="1"
		and target_4.getRightOperand().(VariableAccess).getTarget()=vhsub_156
}

predicate func_5(Variable vvsub_157, BinaryBitwiseOperation target_5) {
		target_5.getLeftOperand().(Literal).getValue()="1"
		and target_5.getRightOperand().(VariableAccess).getTarget()=vvsub_157
}

predicate func_6(Variable vrect_144, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="width"
		and target_6.getQualifier().(VariableAccess).getTarget()=vrect_144
}

predicate func_7(Variable vrect_144, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="height"
		and target_7.getQualifier().(VariableAccess).getTarget()=vrect_144
}

predicate func_11(Variable vrect_144, Variable vhdiv_158, DivExpr target_11) {
		target_11.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_11.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_11.getRightOperand().(VariableAccess).getTarget()=vhdiv_158
}

predicate func_13(Variable vrect_144, Variable vvdiv_159, DivExpr target_13) {
		target_13.getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrect_144
		and target_13.getRightOperand().(VariableAccess).getTarget()=vvdiv_159
}

from Function func, Variable vrect_144, Variable vhsub_156, Variable vvsub_157, Variable vhdiv_158, Variable vvdiv_159, VariableAccess target_0, VariableAccess target_1, BinaryBitwiseOperation target_4, BinaryBitwiseOperation target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, DivExpr target_11, DivExpr target_13
where
func_0(vhdiv_158, target_0)
and func_1(vvdiv_159, target_1)
and not func_2(vrect_144, vhsub_156, target_11, target_4)
and not func_3(vrect_144, vvsub_157, target_13, target_5)
and func_4(vhsub_156, target_4)
and func_5(vvsub_157, target_5)
and func_6(vrect_144, target_6)
and func_7(vrect_144, target_7)
and func_11(vrect_144, vhdiv_158, target_11)
and func_13(vrect_144, vvdiv_159, target_13)
and vrect_144.getType().hasName("LenscorrectionCtx *")
and vhsub_156.getType().hasName("int")
and vvsub_157.getType().hasName("int")
and vhdiv_158.getType().hasName("int")
and vvdiv_159.getType().hasName("int")
and vrect_144.getParentScope+() = func
and vhsub_156.getParentScope+() = func
and vvsub_157.getParentScope+() = func
and vhdiv_158.getParentScope+() = func
and vvdiv_159.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
