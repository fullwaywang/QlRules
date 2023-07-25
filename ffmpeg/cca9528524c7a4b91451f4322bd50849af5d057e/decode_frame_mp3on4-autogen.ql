/**
 * @name ffmpeg-cca9528524c7a4b91451f4322bd50849af5d057e-decode_frame_mp3on4
 * @id cpp/ffmpeg/cca9528524c7a4b91451f4322bd50849af5d057e/decode-frame-mp3on4
 * @description ffmpeg-cca9528524c7a4b91451f4322bd50849af5d057e-libavcodec/mpegaudiodec.c-decode_frame_mp3on4 CVE-2012-2797
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1892, ExprStmt target_2, RelationalOperation target_3) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(PointerFieldAccess).getTarget().getName()="frames"
		and target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1892
		and target_0.getRightOperand() instanceof Literal
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_samples"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1892
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_1892, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_samples"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1892
		and target_2.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_3(Variable vs_1892, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="get_buffer"
		and target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getLesserOperand().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1892
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vs_1892, ExprStmt target_2, RelationalOperation target_3
where
not func_0(vs_1892, target_2, target_3)
and func_2(vs_1892, target_2)
and func_3(vs_1892, target_3)
and vs_1892.getType().hasName("MP3On4DecodeContext *")
and vs_1892.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
