/**
 * @name lz4-13a2d9e34ffc4170720ce417c73e396d0ac1471a-LZ4_compress_generic
 * @id cpp/lz4/13a2d9e34ffc4170720ce417c73e396d0ac1471a/LZ4-compress-generic
 * @description lz4-13a2d9e34ffc4170720ce417c73e396d0ac1471a-lib/lz4.c-LZ4_compress_generic CVE-2019-17543
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="8"
		and not target_0.getValue()="240"
		and target_0.getParent().(RShiftExpr).getParent().(PointerAddExpr).getAnOperand() instanceof BinaryBitwiseOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vmatchCode_1008, ExprStmt target_4, ExprStmt target_5) {
	exists(DivExpr target_1 |
		target_1.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmatchCode_1008
		and target_1.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="240"
		and target_1.getRightOperand().(Literal).getValue()="255"
		and target_4.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignPointerSubExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmatchCode_1008, VariableAccess target_2) {
		target_2.getTarget()=vmatchCode_1008
}

predicate func_3(Variable vmatchCode_1008, BinaryBitwiseOperation target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vmatchCode_1008
		and target_3.getRightOperand() instanceof Literal
}

predicate func_4(Variable vmatchCode_1008, ExprStmt target_4) {
		target_4.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmatchCode_1008
		and target_4.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
}

predicate func_5(Variable vmatchCode_1008, ExprStmt target_5) {
		target_5.getExpr().(AssignPointerSubExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vmatchCode_1008
}

from Function func, Variable vmatchCode_1008, Literal target_0, VariableAccess target_2, BinaryBitwiseOperation target_3, ExprStmt target_4, ExprStmt target_5
where
func_0(func, target_0)
and not func_1(vmatchCode_1008, target_4, target_5)
and func_2(vmatchCode_1008, target_2)
and func_3(vmatchCode_1008, target_3)
and func_4(vmatchCode_1008, target_4)
and func_5(vmatchCode_1008, target_5)
and vmatchCode_1008.getType().hasName("unsigned int")
and vmatchCode_1008.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
