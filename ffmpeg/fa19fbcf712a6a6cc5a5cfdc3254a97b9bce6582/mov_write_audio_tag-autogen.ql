/**
 * @name ffmpeg-fa19fbcf712a6a6cc5a5cfdc3254a97b9bce6582-mov_write_audio_tag
 * @id cpp/ffmpeg/fa19fbcf712a6a6cc5a5cfdc3254a97b9bce6582/mov-write-audio-tag
 * @description ffmpeg-fa19fbcf712a6a6cc5a5cfdc3254a97b9bce6582-libavformat/movenc.c-mov_write_audio_tag CVE-2018-14395
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrack_1018, BlockStmt target_2, EqualityOperation target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_1018
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtrack_1018, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="timescale"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_1018
		and target_1.getLesserOperand().(Literal).getValue()="65535"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vtrack_1018, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("mov_get_lpcm_flags")
		and target_2.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_2.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_2.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_1018
		and target_2.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_2.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(StringLiteral).getValue()="lpcm"
}

predicate func_3(Parameter vtrack_1018, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="mode"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_1018
		and target_3.getAnOperand().(Literal).getValue()="2"
}

from Function func, Parameter vtrack_1018, RelationalOperation target_1, BlockStmt target_2, EqualityOperation target_3
where
not func_0(vtrack_1018, target_2, target_3, target_1)
and func_1(vtrack_1018, target_2, target_1)
and func_2(vtrack_1018, target_2)
and func_3(vtrack_1018, target_3)
and vtrack_1018.getType().hasName("MOVTrack *")
and vtrack_1018.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
