/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-AcquireQuantumMemory
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/AcquireQuantumMemory
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-MagickCore/memory.c-AcquireQuantumMemory CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcount_528, Parameter vquantum_528, Variable vsize_531, VariableAccess target_0) {
		target_0.getTarget()=vsize_531
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_528
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_528
}

predicate func_1(Variable vsize_531, VariableAccess target_1) {
		target_1.getTarget()=vsize_531
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("AcquireMagickMemory")
}

predicate func_2(Parameter vcount_528, Parameter vquantum_528, ExprStmt target_10) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("CheckMemoryOverflow")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vcount_528
		and target_2.getArgument(1).(VariableAccess).getTarget()=vquantum_528
		and target_10.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(LogicalOrExpr target_7, Function func, ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vcount_528, VariableAccess target_5) {
		target_5.getTarget()=vcount_528
}

predicate func_6(Parameter vquantum_528, VariableAccess target_6) {
		target_6.getTarget()=vquantum_528
}

predicate func_7(Parameter vcount_528, Parameter vquantum_528, Variable vsize_531, BlockStmt target_11, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcount_528
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquantum_528
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_531
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vcount_528
		and target_7.getParent().(IfStmt).getThen()=target_11
}

/*predicate func_8(Parameter vcount_528, Variable vsize_531, DivExpr target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=vsize_531
		and target_8.getRightOperand().(VariableAccess).getTarget()=vcount_528
}

*/
predicate func_9(LogicalOrExpr target_7, Function func, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="12"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vcount_528, Parameter vquantum_528, Variable vsize_531, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_531
		and target_10.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_528
		and target_10.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_528
}

predicate func_11(BlockStmt target_11) {
		target_11.getStmt(0) instanceof ExprStmt
		and target_11.getStmt(1) instanceof ReturnStmt
}

from Function func, Parameter vcount_528, Parameter vquantum_528, Variable vsize_531, VariableAccess target_0, VariableAccess target_1, ReturnStmt target_4, VariableAccess target_5, VariableAccess target_6, LogicalOrExpr target_7, ExprStmt target_9, ExprStmt target_10, BlockStmt target_11
where
func_0(vcount_528, vquantum_528, vsize_531, target_0)
and func_1(vsize_531, target_1)
and not func_2(vcount_528, vquantum_528, target_10)
and func_4(target_7, func, target_4)
and func_5(vcount_528, target_5)
and func_6(vquantum_528, target_6)
and func_7(vcount_528, vquantum_528, vsize_531, target_11, target_7)
and func_9(target_7, func, target_9)
and func_10(vcount_528, vquantum_528, vsize_531, target_10)
and func_11(target_11)
and vcount_528.getType().hasName("const size_t")
and vquantum_528.getType().hasName("const size_t")
and vsize_531.getType().hasName("size_t")
and vcount_528.getParentScope+() = func
and vquantum_528.getParentScope+() = func
and vsize_531.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
