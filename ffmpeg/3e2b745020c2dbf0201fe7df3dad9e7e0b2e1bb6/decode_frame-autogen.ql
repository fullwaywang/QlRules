/**
 * @name ffmpeg-3e2b745020c2dbf0201fe7df3dad9e7e0b2e1bb6-decode_frame
 * @id cpp/ffmpeg/3e2b745020c2dbf0201fe7df3dad9e7e0b2e1bb6/decode-frame
 * @description ffmpeg-3e2b745020c2dbf0201fe7df3dad9e7e0b2e1bb6-libavcodec/pngdec.c-decode_frame CVE-2014-8545
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_526, LogicalAndExpr target_2, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_526, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="bit_depth"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_1.getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
}

predicate func_2(Variable vs_526, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_pixel"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_526
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="3"
}

from Function func, Variable vs_526, EqualityOperation target_1, LogicalAndExpr target_2
where
not func_0(vs_526, target_2, target_1)
and func_1(vs_526, target_1)
and func_2(vs_526, target_2)
and vs_526.getType().hasName("PNGDecContext *const")
and vs_526.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
