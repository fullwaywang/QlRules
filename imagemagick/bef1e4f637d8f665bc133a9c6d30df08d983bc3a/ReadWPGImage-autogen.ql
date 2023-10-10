/**
 * @name imagemagick-bef1e4f637d8f665bc133a9c6d30df08d983bc3a-ReadWPGImage
 * @id cpp/imagemagick/bef1e4f637d8f665bc133a9c6d30df08d983bc3a/ReadWPGImage
 * @description imagemagick-bef1e4f637d8f665bc133a9c6d30df08d983bc3a-coders/wpg.c-ReadWPGImage CVE-2016-7533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vldblk_966, ExprStmt target_2, ExprStmt target_3) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vldblk_966
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vldblk_966
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vldblk_966, VariableAccess target_1) {
		target_1.getTarget()=vldblk_966
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

predicate func_2(Variable vldblk_966, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vldblk_966
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_3(Variable vldblk_966, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ReadBlob")
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vldblk_966
}

from Function func, Variable vldblk_966, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vldblk_966, target_2, target_3)
and func_1(vldblk_966, target_1)
and func_2(vldblk_966, target_2)
and func_3(vldblk_966, target_3)
and vldblk_966.getType().hasName("ssize_t")
and vldblk_966.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
