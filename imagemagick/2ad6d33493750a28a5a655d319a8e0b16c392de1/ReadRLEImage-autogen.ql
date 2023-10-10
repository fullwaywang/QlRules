/**
 * @name imagemagick-2ad6d33493750a28a5a655d319a8e0b16c392de1-ReadRLEImage
 * @id cpp/imagemagick/2ad6d33493750a28a5a655d319a8e0b16c392de1/ReadRLEImage
 * @description imagemagick-2ad6d33493750a28a5a655d319a8e0b16c392de1-coders/rle.c-ReadRLEImage CVE-2016-7515
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnumber_planes_175, VariableAccess target_0) {
		target_0.getTarget()=vnumber_planes_175
}

predicate func_1(Variable vnumber_planes_175, VariableAccess target_1) {
		target_1.getTarget()=vnumber_planes_175
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="4"
		and not target_2.getValue()="2"
		and target_2.getParent().(GTExpr).getParent().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vnumber_planes_175, RelationalOperation target_13, Literal target_3) {
		target_3.getValue()="4"
		and not target_3.getValue()="0"
		and target_3.getParent().(ConditionalExpr).getParent().(MulExpr).getRightOperand().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_3.getParent().(ConditionalExpr).getParent().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnumber_planes_175
		and target_3.getParent().(ConditionalExpr).getParent().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable vnumber_planes_175, EqualityOperation target_14) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getTarget()=vnumber_planes_175
		and target_6.getAnOperand().(RemExpr).getRightOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(Literal).getValue()="0"
		and target_14.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vnumber_planes_175, ExprStmt target_15) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getTarget()=vnumber_planes_175
		and target_7.getAnOperand().(Literal).getValue()="1"
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vimage_140, Variable vpixel_info_length_178, ExprStmt target_16, EqualityOperation target_17, ExprStmt target_18) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_length_178
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_10(Variable vimage_140, Variable vnumber_planes_175, Variable vpixel_info_length_178, VariableAccess target_10) {
		target_10.getTarget()=vpixel_info_length_178
		and target_10.getParent().(AssignExpr).getLValue() = target_10
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnumber_planes_175
		and target_10.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getElse() instanceof Literal
}

predicate func_11(Variable vnumber_planes_175, VariableAccess target_11) {
		target_11.getTarget()=vnumber_planes_175
		and target_11.getParent().(GTExpr).getLesserOperand() instanceof Literal
}

predicate func_12(Variable vnumber_planes_175, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vnumber_planes_175
		and target_12.getLesserOperand() instanceof Literal
}

predicate func_13(Variable vnumber_planes_175, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vnumber_planes_175
}

predicate func_14(Variable vnumber_planes_175, EqualityOperation target_14) {
		target_14.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnumber_planes_175
		and target_14.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnumber_planes_175
}

predicate func_15(Variable vimage_140, Variable vnumber_planes_175, Variable vpixel_info_length_178, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_length_178
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnumber_planes_175
		and target_15.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ConditionalExpr).getElse() instanceof Literal
}

predicate func_16(Variable vimage_140, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_140
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_140
}

predicate func_17(Variable vimage_140, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vimage_140
		and target_17.getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Variable vpixel_info_length_178, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_info_length_178
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

from Function func, Variable vimage_140, Variable vnumber_planes_175, Variable vpixel_info_length_178, VariableAccess target_0, VariableAccess target_1, Literal target_2, Literal target_3, VariableAccess target_10, VariableAccess target_11, RelationalOperation target_12, RelationalOperation target_13, EqualityOperation target_14, ExprStmt target_15, ExprStmt target_16, EqualityOperation target_17, ExprStmt target_18
where
func_0(vnumber_planes_175, target_0)
and func_1(vnumber_planes_175, target_1)
and func_2(func, target_2)
and func_3(vnumber_planes_175, target_13, target_3)
and not func_6(vnumber_planes_175, target_14)
and not func_7(vnumber_planes_175, target_15)
and not func_8(vimage_140, vpixel_info_length_178, target_16, target_17, target_18)
and func_10(vimage_140, vnumber_planes_175, vpixel_info_length_178, target_10)
and func_11(vnumber_planes_175, target_11)
and func_12(vnumber_planes_175, target_12)
and func_13(vnumber_planes_175, target_13)
and func_14(vnumber_planes_175, target_14)
and func_15(vimage_140, vnumber_planes_175, vpixel_info_length_178, target_15)
and func_16(vimage_140, target_16)
and func_17(vimage_140, target_17)
and func_18(vpixel_info_length_178, target_18)
and vimage_140.getType().hasName("Image *")
and vnumber_planes_175.getType().hasName("size_t")
and vpixel_info_length_178.getType().hasName("size_t")
and vimage_140.getParentScope+() = func
and vnumber_planes_175.getParentScope+() = func
and vpixel_info_length_178.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
