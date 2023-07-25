/**
 * @name ffmpeg-e43a0a232dbf6d3c161823c2e07c52e76227a1bc-get_video_buffer
 * @id cpp/ffmpeg/e43a0a232dbf6d3c161823c2e07c52e76227a1bc/get-video-buffer
 * @description ffmpeg-e43a0a232dbf6d3c161823c2e07c52e76227a1bc-libavfilter/vf_pad.c-get_video_buffer CVE-2013-4263
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vframe_206, Variable vplane_209, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_1, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_206
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_209
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vframe_206, Variable vplane_209, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vplane_209
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_206
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_209
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Variable vframe_206, Variable vplane_209, BlockStmt target_2) {
		target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_206
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_209
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="x"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="pixelstep"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_209
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="y"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_209
}

predicate func_3(Variable vframe_206, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_206
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Variable vplane_209, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vplane_209
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vframe_206, Variable vplane_209, LogicalAndExpr target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vframe_206, vplane_209, target_2, target_3, target_1, target_4)
and func_1(vframe_206, vplane_209, target_2, target_1)
and func_2(vframe_206, vplane_209, target_2)
and func_3(vframe_206, target_3)
and func_4(vplane_209, target_4)
and vframe_206.getType().hasName("AVFrame *")
and vplane_209.getType().hasName("int")
and vframe_206.(LocalVariable).getFunction() = func
and vplane_209.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
