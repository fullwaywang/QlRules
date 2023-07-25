/**
 * @name ffmpeg-6abb9a901fca27da14d4fffbb01948288b5da3ba-decode_init
 * @id cpp/ffmpeg/6abb9a901fca27da14d4fffbb01948288b5da3ba/decode-init
 * @description ffmpeg-6abb9a901fca27da14d4fffbb01948288b5da3ba-libavcodec/huffyuv.c-decode_init CVE-2013-0848
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_419, Variable vs_421, ExprStmt target_1, IfStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="predictor"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_421
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_419
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_419
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RemExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_419
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="width must be a multiple of 4 this colorspace and predictor\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_419, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_419
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="width must be even for this colorspace\n"
}

predicate func_2(Parameter vavctx_419, Variable vs_421, IfStmt target_2) {
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="bgr32"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_421
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_419
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_419
}

predicate func_3(Variable vs_421, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("alloc_temp")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_421
}

from Function func, Parameter vavctx_419, Variable vs_421, ExprStmt target_1, IfStmt target_2, ExprStmt target_3
where
not func_0(vavctx_419, vs_421, target_1, target_2, target_3, func)
and func_1(vavctx_419, target_1)
and func_2(vavctx_419, vs_421, target_2)
and func_3(vs_421, target_3)
and vavctx_419.getType().hasName("AVCodecContext *")
and vs_421.getType().hasName("HYuvContext *")
and vavctx_419.getFunction() = func
and vs_421.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
