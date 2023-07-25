/**
 * @name ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-matroska_deliver_packet
 * @id cpp/ffmpeg/77d2ef13a8fa630e5081f14bde3fd20f84c90aec/matroska-deliver-packet
 * @description ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-libavformat/matroskadec.c-matroska_deliver_packet CVE-2011-3504
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("void *")
		and target_0.getRValue() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vmatroska_1600, RelationalOperation target_4, MulExpr target_5, ExprStmt target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("void *")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packets"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vmatroska_1600, FunctionCall target_3) {
		target_3.getTarget().hasName("av_realloc")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="packets"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_3.getArgument(1).(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_packets"
		and target_3.getArgument(1).(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_3.getArgument(1).(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packets"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
}

predicate func_4(Parameter vmatroska_1600, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_packets"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_4.getLesserOperand().(Literal).getValue()="1"
}

predicate func_5(Parameter vmatroska_1600, MulExpr target_5) {
		target_5.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_packets"
		and target_5.getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_5.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getRightOperand().(SizeofTypeOperator).getValue()="8"
}

predicate func_6(Parameter vmatroska_1600, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packets"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatroska_1600
		and target_6.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

from Function func, Parameter vmatroska_1600, FunctionCall target_3, RelationalOperation target_4, MulExpr target_5, ExprStmt target_6
where
not func_0(func)
and not func_1(vmatroska_1600, target_4, target_5, target_6)
and func_3(vmatroska_1600, target_3)
and func_4(vmatroska_1600, target_4)
and func_5(vmatroska_1600, target_5)
and func_6(vmatroska_1600, target_6)
and vmatroska_1600.getType().hasName("MatroskaDemuxContext *")
and vmatroska_1600.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
