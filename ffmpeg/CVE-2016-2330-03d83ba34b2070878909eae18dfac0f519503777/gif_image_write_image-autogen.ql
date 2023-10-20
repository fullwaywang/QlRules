/**
 * @name ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-gif_image_write_image
 * @id cpp/ffmpeg/03d83ba34b2070878909eae18dfac0f519503777/gif-image-write-image
 * @description ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-libavcodec/gif.c-gif_image_write_image CVE-2016-2330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_82, ExprStmt target_2, ArrayExpr target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="buf_size"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_82
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_82, Variable vheight_83, Variable vwidth_83, MulExpr target_1) {
		target_1.getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_83
		and target_1.getRightOperand().(VariableAccess).getTarget()=vheight_83
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_lzw_encode_init")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="lzw"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_82
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_82
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="12"
}

predicate func_2(Variable vs_82, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ff_lzw_encode_init")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="lzw"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_82
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_82
		and target_2.getExpr().(FunctionCall).getArgument(2) instanceof MulExpr
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="12"
}

predicate func_3(Variable vs_82, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_82
		and target_3.getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable vs_82, Variable vheight_83, Variable vwidth_83, MulExpr target_1, ExprStmt target_2, ArrayExpr target_3
where
not func_0(vs_82, target_2, target_3)
and func_1(vs_82, vheight_83, vwidth_83, target_1)
and func_2(vs_82, target_2)
and func_3(vs_82, target_3)
and vs_82.getType().hasName("GIFContext *")
and vheight_83.getType().hasName("int")
and vwidth_83.getType().hasName("int")
and vs_82.getParentScope+() = func
and vheight_83.getParentScope+() = func
and vwidth_83.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
