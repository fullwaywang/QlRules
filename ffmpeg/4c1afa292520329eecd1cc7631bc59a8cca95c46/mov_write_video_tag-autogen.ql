/**
 * @name ffmpeg-4c1afa292520329eecd1cc7631bc59a8cca95c46-mov_write_video_tag
 * @id cpp/ffmpeg/4c1afa292520329eecd1cc7631bc59a8cca95c46/mov-write-video-tag
 * @description ffmpeg-4c1afa292520329eecd1cc7631bc59a8cca95c46-libavformat/movenc.c-mov_write_video_tag CVE-2020-22015
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrack_2097, LogicalAndExpr target_6, BinaryBitwiseOperation target_2, ArrayExpr target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpal_size_2163, LogicalAndExpr target_6, SubExpr target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpal_size_2163
		and target_1.getExpr().(AssignExpr).getRValue() instanceof BinaryBitwiseOperation
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtrack_2097, BinaryBitwiseOperation target_2) {
		target_2.getLeftOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(PointerFieldAccess).getTarget().getName()="bits_per_coded_sample"
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
}

predicate func_4(Function func, Initializer target_4) {
		target_4.getExpr() instanceof BinaryBitwiseOperation
		and target_4.getExpr().getEnclosingFunction() = func
}

predicate func_5(LogicalAndExpr target_6, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vtrack_2097, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="format"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
}

predicate func_7(Parameter vtrack_2097, ArrayExpr target_7) {
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="palette"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_2097
}

predicate func_8(Variable vpal_size_2163, SubExpr target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=vpal_size_2163
		and target_8.getRightOperand().(Literal).getValue()="1"
}

from Function func, Parameter vtrack_2097, Variable vpal_size_2163, BinaryBitwiseOperation target_2, Initializer target_4, DeclStmt target_5, LogicalAndExpr target_6, ArrayExpr target_7, SubExpr target_8
where
not func_0(vtrack_2097, target_6, target_2, target_7)
and not func_1(vpal_size_2163, target_6, target_8)
and func_2(vtrack_2097, target_2)
and func_4(func, target_4)
and func_5(target_6, func, target_5)
and func_6(vtrack_2097, target_6)
and func_7(vtrack_2097, target_7)
and func_8(vpal_size_2163, target_8)
and vtrack_2097.getType().hasName("MOVTrack *")
and vpal_size_2163.getType().hasName("int")
and vtrack_2097.getParentScope+() = func
and vpal_size_2163.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
