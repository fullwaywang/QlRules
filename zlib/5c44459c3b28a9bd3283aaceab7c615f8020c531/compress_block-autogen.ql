/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-compress_block
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/compress-block
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-trees.c-compress_block CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Parameter vs_0, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="last_lit"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_2(Parameter vs_0, Variable vlx_1072, VariableAccess target_2) {
		target_2.getTarget()=vlx_1072
		and target_2.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_2.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

/*predicate func_3(Parameter vs_0, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="last_lit"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_0
}

*/
predicate func_4(Parameter vs_0, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="l_buf"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_5(Variable vlx_1072, VariableAccess target_5) {
		target_5.getTarget()=vlx_1072
}

predicate func_6(Parameter vs_0, Variable vdist_1070, RelationalOperation target_10) {
	exists(BitwiseAndExpr target_6 |
		target_6.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_6.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_6.getLeftOperand().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_6.getRightOperand().(HexLiteral).getValue()="255"
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdist_1070
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vs_0, Variable vdist_1070, ExprStmt target_12, ExprStmt target_13, EqualityOperation target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vdist_1070
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255"
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_7.getExpr().(AssignAddExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vs_0, VariableAccess target_8) {
		target_8.getTarget()=vs_0
}

predicate func_9(Parameter vs_0, Variable vdist_1070, Variable vlx_1072, ArrayExpr target_9) {
		target_9.getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_9.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_9.getArrayOffset().(VariableAccess).getTarget()=vlx_1072
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdist_1070
}

predicate func_10(Parameter vs_0, Variable vlx_1072, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vlx_1072
		and target_10.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_12(Parameter vs_0, Variable vlx_1072, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vlx_1072
}

predicate func_13(Variable vdist_1070, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdist_1070
		and target_13.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
}

predicate func_14(Variable vdist_1070, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vdist_1070
		and target_14.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vs_0, Variable vdist_1070, Variable vlx_1072, Initializer target_0, PointerFieldAccess target_1, VariableAccess target_2, PointerFieldAccess target_4, VariableAccess target_5, VariableAccess target_8, ArrayExpr target_9, RelationalOperation target_10, ExprStmt target_12, ExprStmt target_13, EqualityOperation target_14
where
func_0(func, target_0)
and func_1(vs_0, target_1)
and func_2(vs_0, vlx_1072, target_2)
and func_4(vs_0, target_4)
and func_5(vlx_1072, target_5)
and not func_6(vs_0, vdist_1070, target_10)
and not func_7(vs_0, vdist_1070, target_12, target_13, target_14)
and func_8(vs_0, target_8)
and func_9(vs_0, vdist_1070, vlx_1072, target_9)
and func_10(vs_0, vlx_1072, target_10)
and func_12(vs_0, vlx_1072, target_12)
and func_13(vdist_1070, target_13)
and func_14(vdist_1070, target_14)
and vs_0.getType().hasName("deflate_state *")
and vdist_1070.getType().hasName("unsigned int")
and vlx_1072.getType().hasName("unsigned int")
and vs_0.getParentScope+() = func
and vdist_1070.getParentScope+() = func
and vlx_1072.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
