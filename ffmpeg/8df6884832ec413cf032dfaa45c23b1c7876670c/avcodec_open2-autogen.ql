/**
 * @name ffmpeg-8df6884832ec413cf032dfaa45c23b1c7876670c-avcodec_open2
 * @id cpp/ffmpeg/8df6884832ec413cf032dfaa45c23b1c7876670c/avcodec-open2
 * @description ffmpeg-8df6884832ec413cf032dfaa45c23b1c7876670c-libavcodec/utils.c-avcodec_open2 CVE-2019-17539
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_542, ExprStmt target_2, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="codec"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="close"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="caps_internal"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_542, ExprStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="codec"
		and target_1.getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="caps_internal"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vavctx_542, ExprStmt target_2) {
		target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="close"
		and target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_2.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vavctx_542
}

predicate func_3(Parameter vavctx_542, LogicalAndExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="codec"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="caps_internal"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_542
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
}

from Function func, Parameter vavctx_542, PointerFieldAccess target_1, ExprStmt target_2, LogicalAndExpr target_3
where
not func_0(vavctx_542, target_2, target_3)
and func_1(vavctx_542, target_2, target_1)
and func_2(vavctx_542, target_2)
and func_3(vavctx_542, target_3)
and vavctx_542.getType().hasName("AVCodecContext *")
and vavctx_542.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
