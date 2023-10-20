/**
 * @name ffmpeg-2d1c0dea5f6b91bec7f5fa53ec050913d851e366-dv_extract_audio
 * @id cpp/ffmpeg/2d1c0dea5f6b91bec7f5fa53ec050913d851e366/dv-extract-audio
 * @description ffmpeg-2d1c0dea5f6b91bec7f5fa53ec050913d851e366-libavformat/dv.c-dv_extract_audio CVE-2011-3929
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpcm_111, Variable vipcm_111, Parameter vppcm_105, ArrayExpr target_0) {
		target_0.getArrayBase().(VariableAccess).getTarget()=vppcm_105
		and target_0.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vipcm_111
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpcm_111
}

predicate func_1(Variable vpcm_111, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpcm_111
		and target_1.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vpcm_111, Variable vipcm_111, Parameter vppcm_105, ArrayExpr target_0, ExprStmt target_1
where
func_0(vpcm_111, vipcm_111, vppcm_105, target_0)
and func_1(vpcm_111, func, target_1)
and vpcm_111.getType().hasName("uint8_t *")
and vipcm_111.getType().hasName("uint8_t")
and vppcm_105.getType().hasName("uint8_t *[4]")
and vpcm_111.(LocalVariable).getFunction() = func
and vipcm_111.(LocalVariable).getFunction() = func
and vppcm_105.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
