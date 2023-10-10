/**
 * @name imagemagick-91cc3f36f2ccbd485a0456bab9aebe63b635da88-WritePSDChannel
 * @id cpp/imagemagick/91cc3f36f2ccbd485a0456bab9aebe63b635da88/WritePSDChannel
 * @description imagemagick-91cc3f36f2ccbd485a0456bab9aebe63b635da88-coders/psd.c-WritePSDChannel CVE-2017-5510
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_2460, ExprStmt target_1, ExprStmt target_2, VariableAccess target_0) {
		target_0.getTarget()=vimage_2460
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumInfo")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Parameter vimage_2460, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("IsImageMonochrome")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_2460
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_2460
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vimage_2460, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PSDPackbitsEncodeImage")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_2460
}

from Function func, Parameter vimage_2460, VariableAccess target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(vimage_2460, target_1, target_2, target_0)
and func_1(vimage_2460, target_1)
and func_2(vimage_2460, target_2)
and vimage_2460.getType().hasName("Image *")
and vimage_2460.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
