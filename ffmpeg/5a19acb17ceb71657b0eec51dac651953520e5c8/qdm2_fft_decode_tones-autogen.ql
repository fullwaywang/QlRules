/**
 * @name ffmpeg-5a19acb17ceb71657b0eec51dac651953520e5c8-qdm2_fft_decode_tones
 * @id cpp/ffmpeg/5a19acb17ceb71657b0eec51dac651953520e5c8/qdm2-fft-decode-tones
 * @description ffmpeg-5a19acb17ceb71657b0eec51dac651953520e5c8-libavcodec/qdm2.c-qdm2_fft_decode_tones CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlocal_int_14_1322, ExprStmt target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlocal_int_14_1322
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="256"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlocal_int_14_1322, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlocal_int_14_1322
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Variable vlocal_int_14_1322, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="fft_level_exp"
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("QDM2Context *")
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlocal_int_14_1322
}

from Function func, Variable vlocal_int_14_1322, ExprStmt target_1, ExprStmt target_2
where
not func_0(vlocal_int_14_1322, target_1, target_2)
and func_1(vlocal_int_14_1322, target_1)
and func_2(vlocal_int_14_1322, target_2)
and vlocal_int_14_1322.getType().hasName("int")
and vlocal_int_14_1322.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
