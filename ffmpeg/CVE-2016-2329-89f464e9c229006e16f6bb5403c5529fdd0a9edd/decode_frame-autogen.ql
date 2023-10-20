/**
 * @name ffmpeg-89f464e9c229006e16f6bb5403c5529fdd0a9edd-decode_frame
 * @id cpp/ffmpeg/89f464e9c229006e16f6bb5403c5529fdd0a9edd/decode-frame
 * @description ffmpeg-89f464e9c229006e16f6bb5403c5529fdd0a9edd-libavcodec/tiff.c-decode_frame CVE-2016-2329
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1172, BlockStmt target_2, SubExpr target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rps"
		and target_0.getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1172
		and target_0.getAnOperand().(RemExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="subsampling"
		and target_0.getAnOperand().(RemExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1172
		and target_0.getAnOperand().(RemExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RemExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1172, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="rps"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1172
		and target_1.getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vs_1172, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="rps %d invalid\n"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rps"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1172
}

predicate func_3(Variable vs_1172, SubExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getRightOperand().(PointerFieldAccess).getTarget().getName()="strippos"
		and target_3.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1172
}

from Function func, Variable vs_1172, RelationalOperation target_1, BlockStmt target_2, SubExpr target_3
where
not func_0(vs_1172, target_2, target_3, target_1)
and func_1(vs_1172, target_2, target_1)
and func_2(vs_1172, target_2)
and func_3(vs_1172, target_3)
and vs_1172.getType().hasName("TiffContext *const")
and vs_1172.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
