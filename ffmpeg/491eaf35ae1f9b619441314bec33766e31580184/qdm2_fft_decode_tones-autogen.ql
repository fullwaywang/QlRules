/**
 * @name ffmpeg-491eaf35ae1f9b619441314bec33766e31580184-qdm2_fft_decode_tones
 * @id cpp/ffmpeg/491eaf35ae1f9b619441314bec33766e31580184/qdm2-fft-decode-tones
 * @description ffmpeg-491eaf35ae1f9b619441314bec33766e31580184-libavcodec/qdm2.c-qdm2_fft_decode_tones CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlocal_int_14_1321, ExprStmt target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlocal_int_14_1321
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="256"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlocal_int_14_1321, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlocal_int_14_1321
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Variable vlocal_int_14_1321, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="fft_level_exp"
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("QDM2Context *")
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlocal_int_14_1321
}

from Function func, Variable vlocal_int_14_1321, ExprStmt target_1, ExprStmt target_2
where
not func_0(vlocal_int_14_1321, target_1, target_2)
and func_1(vlocal_int_14_1321, target_1)
and func_2(vlocal_int_14_1321, target_2)
and vlocal_int_14_1321.getType().hasName("int")
and vlocal_int_14_1321.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
