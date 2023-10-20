/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-AcquireVirtualMemory
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/AcquireVirtualMemory
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-MagickCore/memory.c-AcquireVirtualMemory CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcount_567, Parameter vquantum_568, Variable vlength_574, VariableAccess target_0) {
		target_0.getTarget()=vlength_574
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_567
		and target_0.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_568
}

predicate func_1(Variable vlength_574, VariableAccess target_1) {
		target_1.getTarget()=vlength_574
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
}

predicate func_2(Variable vlength_574, VariableAccess target_2) {
		target_2.getTarget()=vlength_574
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("AcquireMagickResource")
}

predicate func_3(Variable vlength_574, VariableAccess target_3) {
		target_3.getTarget()=vlength_574
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireAlignedMemory")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
}

predicate func_4(Variable vlength_574, VariableAccess target_4) {
		target_4.getTarget()=vlength_574
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
}

predicate func_5(Variable vlength_574, VariableAccess target_5) {
		target_5.getTarget()=vlength_574
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("AcquireMagickResource")
}

predicate func_6(Variable vlength_574, VariableAccess target_6) {
		target_6.getTarget()=vlength_574
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("MapBlob")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Variable vlength_574, VariableAccess target_7) {
		target_7.getTarget()=vlength_574
		and target_7.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("AcquireMagickResource")
}

predicate func_8(Variable vlength_574, VariableAccess target_8) {
		target_8.getTarget()=vlength_574
}

predicate func_9(Variable vlength_574, VariableAccess target_9) {
		target_9.getTarget()=vlength_574
}

predicate func_10(Variable vlength_574, VariableAccess target_10) {
		target_10.getTarget()=vlength_574
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("MapBlob")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_11(Variable vlength_574, VariableAccess target_11) {
		target_11.getTarget()=vlength_574
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
}

predicate func_12(Variable vlength_574, VariableAccess target_12) {
		target_12.getTarget()=vlength_574
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("RelinquishMagickResource")
}

predicate func_13(Variable vlength_574, VariableAccess target_13) {
		target_13.getTarget()=vlength_574
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireMagickMemory")
}

predicate func_14(Parameter vcount_567, Parameter vquantum_568, ExprStmt target_22) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("CheckMemoryOverflow")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vcount_567
		and target_14.getArgument(1).(VariableAccess).getTarget()=vquantum_568
		and target_22.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_16(LogicalOrExpr target_19, Function func, ReturnStmt target_16) {
		target_16.getExpr().(Literal).getValue()="0"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Parameter vcount_567, VariableAccess target_17) {
		target_17.getTarget()=vcount_567
}

predicate func_18(Parameter vquantum_568, VariableAccess target_18) {
		target_18.getTarget()=vquantum_568
}

predicate func_19(Parameter vcount_567, Parameter vquantum_568, Variable vlength_574, BlockStmt target_23, LogicalOrExpr target_19) {
		target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcount_567
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquantum_568
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_574
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vcount_567
		and target_19.getParent().(IfStmt).getThen()=target_23
}

/*predicate func_20(Parameter vcount_567, Variable vlength_574, DivExpr target_20) {
		target_20.getLeftOperand().(VariableAccess).getTarget()=vlength_574
		and target_20.getRightOperand().(VariableAccess).getTarget()=vcount_567
}

*/
predicate func_21(LogicalOrExpr target_19, Function func, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="12"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Parameter vcount_567, Parameter vquantum_568, Variable vlength_574, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_574
		and target_22.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_567
		and target_22.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vquantum_568
}

predicate func_23(BlockStmt target_23) {
		target_23.getStmt(0) instanceof ExprStmt
		and target_23.getStmt(1) instanceof ReturnStmt
}

from Function func, Parameter vcount_567, Parameter vquantum_568, Variable vlength_574, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, VariableAccess target_13, ReturnStmt target_16, VariableAccess target_17, VariableAccess target_18, LogicalOrExpr target_19, ExprStmt target_21, ExprStmt target_22, BlockStmt target_23
where
func_0(vcount_567, vquantum_568, vlength_574, target_0)
and func_1(vlength_574, target_1)
and func_2(vlength_574, target_2)
and func_3(vlength_574, target_3)
and func_4(vlength_574, target_4)
and func_5(vlength_574, target_5)
and func_6(vlength_574, target_6)
and func_7(vlength_574, target_7)
and func_8(vlength_574, target_8)
and func_9(vlength_574, target_9)
and func_10(vlength_574, target_10)
and func_11(vlength_574, target_11)
and func_12(vlength_574, target_12)
and func_13(vlength_574, target_13)
and not func_14(vcount_567, vquantum_568, target_22)
and func_16(target_19, func, target_16)
and func_17(vcount_567, target_17)
and func_18(vquantum_568, target_18)
and func_19(vcount_567, vquantum_568, vlength_574, target_23, target_19)
and func_21(target_19, func, target_21)
and func_22(vcount_567, vquantum_568, vlength_574, target_22)
and func_23(target_23)
and vcount_567.getType().hasName("const size_t")
and vquantum_568.getType().hasName("const size_t")
and vlength_574.getType().hasName("size_t")
and vcount_567.getParentScope+() = func
and vquantum_568.getParentScope+() = func
and vlength_574.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
