/**
 * @name ffmpeg-d85b3c4fff4c4b255232fcc01edbd57f19d60998-ff_vp56_decode_frame
 * @id cpp/ffmpeg/d85b3c4fff4c4b255232fcc01edbd57f19d60998/ff-vp56-decode-frame
 * @description ffmpeg-d85b3c4fff4c4b255232fcc01edbd57f19d60998-libavcodec/vp56.c-ff_vp56_decode_frame CVE-2012-2783
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_493, Variable vp_494, ExprStmt target_2, ExprStmt target_3, ArrayExpr target_4, LogicalOrExpr target_5, ExprStmt target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof ArrayExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_494
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof ArrayExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_493, ExprStmt target_2, ArrayExpr target_1) {
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_1.getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vs_493, ExprStmt target_2) {
		target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="release_buffer"
		and target_2.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_2.getExpr().(VariableCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
}

predicate func_3(Variable vs_493, ExprStmt target_3) {
		target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="block_offset"
		and target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
}

predicate func_4(Variable vs_493, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
}

predicate func_5(Variable vp_494, LogicalOrExpr target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="key_frame"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_494
		and target_5.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_6(Variable vs_493, Variable vp_494, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="framep"
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_493
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_494
}

from Function func, Variable vs_493, Variable vp_494, ArrayExpr target_1, ExprStmt target_2, ExprStmt target_3, ArrayExpr target_4, LogicalOrExpr target_5, ExprStmt target_6
where
not func_0(vs_493, vp_494, target_2, target_3, target_4, target_5, target_6)
and func_1(vs_493, target_2, target_1)
and func_2(vs_493, target_2)
and func_3(vs_493, target_3)
and func_4(vs_493, target_4)
and func_5(vp_494, target_5)
and func_6(vs_493, vp_494, target_6)
and vs_493.getType().hasName("VP56Context *")
and vp_494.getType().hasName("AVFrame *const")
and vs_493.(LocalVariable).getFunction() = func
and vp_494.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
