/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-ResizeQuantumMemory
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/ResizeQuantumMemory
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-MagickCore/memory.c-ResizeQuantumMemory CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcount_1207, Parameter vquantum_1208, Variable vsize_1211, VariableAccess target_0) {
		target_0.getTarget()=vsize_1211
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_1207
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_1208
}

predicate func_1(Variable vsize_1211, VariableAccess target_1) {
		target_1.getTarget()=vsize_1211
		and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ResizeMagickMemory")
}

predicate func_2(Parameter vcount_1207, Parameter vquantum_1208, ExprStmt target_9) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("CheckMemoryOverflow")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vcount_1207
		and target_2.getArgument(1).(VariableAccess).getTarget()=vquantum_1208
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vcount_1207, VariableAccess target_4) {
		target_4.getTarget()=vcount_1207
}

predicate func_5(Parameter vquantum_1208, VariableAccess target_5) {
		target_5.getTarget()=vquantum_1208
}

predicate func_6(Parameter vcount_1207, Parameter vquantum_1208, Variable vsize_1211, BlockStmt target_10, LogicalOrExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcount_1207
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquantum_1208
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_1211
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vcount_1207
		and target_6.getParent().(IfStmt).getThen()=target_10
}

/*predicate func_7(Parameter vcount_1207, Variable vsize_1211, DivExpr target_7) {
		target_7.getLeftOperand().(VariableAccess).getTarget()=vsize_1211
		and target_7.getRightOperand().(VariableAccess).getTarget()=vcount_1207
}

*/
predicate func_8(LogicalOrExpr target_6, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="12"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vcount_1207, Parameter vquantum_1208, Variable vsize_1211, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_1211
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_1207
		and target_9.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_1208
}

predicate func_10(BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_10.getStmt(1) instanceof ExprStmt
		and target_10.getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vcount_1207, Parameter vquantum_1208, Variable vsize_1211, VariableAccess target_0, VariableAccess target_1, VariableAccess target_4, VariableAccess target_5, LogicalOrExpr target_6, ExprStmt target_8, ExprStmt target_9, BlockStmt target_10
where
func_0(vcount_1207, vquantum_1208, vsize_1211, target_0)
and func_1(vsize_1211, target_1)
and not func_2(vcount_1207, vquantum_1208, target_9)
and func_4(vcount_1207, target_4)
and func_5(vquantum_1208, target_5)
and func_6(vcount_1207, vquantum_1208, vsize_1211, target_10, target_6)
and func_8(target_6, func, target_8)
and func_9(vcount_1207, vquantum_1208, vsize_1211, target_9)
and func_10(target_10)
and vcount_1207.getType().hasName("const size_t")
and vquantum_1208.getType().hasName("const size_t")
and vsize_1211.getType().hasName("size_t")
and vcount_1207.getParentScope+() = func
and vquantum_1208.getParentScope+() = func
and vsize_1211.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
