/**
 * @name openjpeg-a1d32a596a94280178c44a55d7e7f1acd992ed5d-opj_t1_encode_cblks
 * @id cpp/openjpeg/a1d32a596a94280178c44a55d7e7f1acd992ed5d/opj-t1-encode-cblks
 * @description openjpeg-a1d32a596a94280178c44a55d7e7f1acd992ed5d-src/lib/openjp2/t1.c-opj_t1_encode_cblks CVE-2018-5727
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtileIndex_2143, ExprStmt target_5) {
	exists(AssignLShiftExpr target_0 |
		target_0.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("OPJ_UINT32 *")
		and target_0.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtileIndex_2143
		and target_0.getRValue() instanceof SubExpr
		and target_0.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Function func, SubExpr target_1) {
		target_1.getValue()="6"
		and target_1.getEnclosingFunction() = func
}

/*predicate func_2(Variable vtiledp_2139, Variable vtileIndex_2143, VariableAccess target_2) {
		target_2.getTarget()=vtileIndex_2143
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtiledp_2139
}

*/
/*predicate func_3(Variable vtiledp_2139, Variable vtileIndex_2143, VariableAccess target_3) {
		target_3.getTarget()=vtiledp_2139
		and target_3.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtileIndex_2143
}

*/
predicate func_4(Variable vtiledp_2139, Variable vtileIndex_2143, AssignMulExpr target_4) {
		target_4.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtiledp_2139
		and target_4.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtileIndex_2143
		and target_4.getRValue().(BinaryBitwiseOperation).getValue()="64"
}

predicate func_5(Variable vtileIndex_2143, ExprStmt target_5) {
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vtileIndex_2143
}

from Function func, Variable vtiledp_2139, Variable vtileIndex_2143, SubExpr target_1, AssignMulExpr target_4, ExprStmt target_5
where
not func_0(vtileIndex_2143, target_5)
and func_1(func, target_1)
and func_4(vtiledp_2139, vtileIndex_2143, target_4)
and func_5(vtileIndex_2143, target_5)
and vtiledp_2139.getType().hasName("OPJ_INT32 *__restrict__")
and vtileIndex_2143.getType().hasName("OPJ_SIZE_T")
and vtiledp_2139.getParentScope+() = func
and vtileIndex_2143.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
