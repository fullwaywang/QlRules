/**
 * @name ffmpeg-296debd213bd6dce7647cedd34eb64e5b94cdc92-dnxhd_decode_header
 * @id cpp/ffmpeg/296debd213bd6dce7647cedd34eb64e5b94cdc92/dnxhd-decode-header
 * @description ffmpeg-296debd213bd6dce7647cedd34eb64e5b94cdc92-libavcodec/dnxhddec.c-dnxhd_decode_header CVE-2017-11719
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_176, ExprStmt target_4, RelationalOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof RelationalOperation
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="mb height too big: %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_0)
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vctx_176, Parameter vframe_176, BlockStmt target_6, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_1.getLesserOperand().(Literal).getValue()="68"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="interlaced_frame"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_176
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="15"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_2(Parameter vctx_176, Parameter vframe_176, BlockStmt target_6, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_2.getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_2.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="interlaced_frame"
		and target_2.getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_176
		and target_2.getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_2.getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="15"
		and target_2.getLesserOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="68"
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_3(BlockStmt target_6, Function func, LogicalOrExpr target_3) {
		target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getParent().(IfStmt).getThen()=target_6
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vctx_176, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data_offset"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_4.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="640"
}

predicate func_5(Parameter vctx_176, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data_offset"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
}

predicate func_6(Parameter vctx_176, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="mb height too big: %d\n"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="mb_height"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_176
}

from Function func, Parameter vctx_176, Parameter vframe_176, LogicalOrExpr target_3, ExprStmt target_4, RelationalOperation target_5, BlockStmt target_6
where
not func_0(vctx_176, target_4, target_5, func)
and func_3(target_6, func, target_3)
and func_4(vctx_176, target_4)
and func_5(vctx_176, target_5)
and func_6(vctx_176, target_6)
and vctx_176.getType().hasName("DNXHDContext *")
and vframe_176.getType().hasName("AVFrame *")
and vctx_176.getParentScope+() = func
and vframe_176.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
