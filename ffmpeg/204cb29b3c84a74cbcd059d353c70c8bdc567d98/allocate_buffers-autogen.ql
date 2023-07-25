/**
 * @name ffmpeg-204cb29b3c84a74cbcd059d353c70c8bdc567d98-allocate_buffers
 * @id cpp/ffmpeg/204cb29b3c84a74cbcd059d353c70c8bdc567d98/allocate-buffers
 * @description ffmpeg-204cb29b3c84a74cbcd059d353c70c8bdc567d98-libavcodec/shorten.c-allocate_buffers CVE-2012-0858
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_122, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="decoded"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_1(Parameter vs_122, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="decoded"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_2(Parameter vs_122, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="decoded"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_3(Parameter vs_122, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="decoded"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_4(Parameter vs_122) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="decoded_base"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_122)
}

predicate func_6(Variable vchan_124, Parameter vs_122, ExprStmt target_12, ExprStmt target_14) {
	exists(AssignExpr target_6 |
		target_6.getLValue() instanceof ArrayExpr
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="decoded_base"
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vchan_124
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nwrap"
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_6.getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_7(Variable vchan_124, Parameter vs_122, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="decoded"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_122
		and target_7.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vchan_124
}

*/
predicate func_8(Variable vchan_124, Parameter vs_122, ArrayExpr target_8) {
		target_8.getArrayBase().(PointerFieldAccess).getTarget().getName()="decoded"
		and target_8.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vchan_124
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("void *")
}

predicate func_9(Parameter vs_122, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="nwrap"
		and target_9.getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_10(Function func, SizeofTypeOperator target_10) {
		target_10.getType() instanceof LongType
		and target_10.getValue()="4"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vchan_124, Parameter vs_122, AssignPointerAddExpr target_11) {
		target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="decoded"
		and target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_11.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vchan_124
		and target_11.getRValue().(PointerFieldAccess).getTarget().getName()="nwrap"
		and target_11.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
}

predicate func_12(Variable vchan_124, Parameter vs_122, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="decoded"
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vchan_124
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_14(Parameter vs_122, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int *")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="coeffs"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nwrap"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_122
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
}

from Function func, Variable vchan_124, Parameter vs_122, PointerFieldAccess target_0, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, ArrayExpr target_8, PointerFieldAccess target_9, SizeofTypeOperator target_10, AssignPointerAddExpr target_11, ExprStmt target_12, ExprStmt target_14
where
func_0(vs_122, target_0)
and func_1(vs_122, target_1)
and func_2(vs_122, target_2)
and func_3(vs_122, target_3)
and not func_4(vs_122)
and not func_6(vchan_124, vs_122, target_12, target_14)
and func_8(vchan_124, vs_122, target_8)
and func_9(vs_122, target_9)
and func_10(func, target_10)
and func_11(vchan_124, vs_122, target_11)
and func_12(vchan_124, vs_122, target_12)
and func_14(vs_122, target_14)
and vchan_124.getType().hasName("int")
and vs_122.getType().hasName("ShortenContext *")
and vchan_124.(LocalVariable).getFunction() = func
and vs_122.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
