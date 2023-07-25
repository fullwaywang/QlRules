/**
 * @name imagemagick-1aa0c6dab6dcef4d9bc3571866ae1c1ddbec7d8f-ReadSUNImage
 * @id cpp/imagemagick/1aa0c6dab6dcef4d9bc3571866ae1c1ddbec7d8f/ReadSUNImage
 * @description imagemagick-1aa0c6dab6dcef4d9bc3571866ae1c1ddbec7d8f-coders/sun.c-ReadSUNImage CVE-2015-8958
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsun_info_265, Variable vheight_428, EqualityOperation target_14, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheight_428
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="height"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsun_info_265
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_1(Variable vbytes_per_line_256, EqualityOperation target_14, ExprStmt target_1) {
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_1.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="15"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_2(Variable vbytes_per_line_256, EqualityOperation target_14, ExprStmt target_2) {
		target_2.getExpr().(AssignLShiftExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_2.getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_3(Variable vbytes_per_line_256, EqualityOperation target_14, ExprStmt target_3) {
		target_3.getExpr().(AssignRShiftExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_3.getExpr().(AssignRShiftExpr).getRValue().(Literal).getValue()="4"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_4(Variable vbytes_per_line_256, Variable vsun_pixels_269, Variable vheight_428, EqualityOperation target_14, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsun_pixels_269
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheight_428
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_5(Variable vsun_data_268, EqualityOperation target_14, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsun_data_268
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsun_data_268
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_6(Variable vbytes_per_line_256, Variable vsun_info_265, Variable vsun_data_268, Variable vsun_pixels_269, Variable vheight_428, EqualityOperation target_14, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("DecodeImage")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsun_data_268
		and target_6.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="length"
		and target_6.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsun_info_265
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsun_pixels_269
		and target_6.getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_6.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vheight_428
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_7(EqualityOperation target_14, Function func, EmptyStmt target_7) {
		target_7.toString() = ";"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_7.getEnclosingFunction() = func
}

predicate func_8(EqualityOperation target_14, Function func, EmptyStmt target_8) {
		target_8.toString() = ";"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_8.getEnclosingFunction() = func
}

predicate func_9(EqualityOperation target_14, Function func, EmptyStmt target_9) {
		target_9.toString() = ";"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_9.getEnclosingFunction() = func
}

predicate func_11(Variable vsun_data_268, Variable vsun_pixels_269, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsun_pixels_269
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsun_data_268
}

predicate func_12(Variable vbytes_per_line_256, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_line_256
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_13(EqualityOperation target_14, Function func, DeclStmt target_13) {
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Variable vsun_info_265, EqualityOperation target_14) {
		target_14.getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsun_info_265
		and target_14.getAnOperand().(Literal).getValue()="2"
}

from Function func, Variable vbytes_per_line_256, Variable vsun_info_265, Variable vsun_data_268, Variable vsun_pixels_269, Variable vheight_428, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, EmptyStmt target_7, EmptyStmt target_8, EmptyStmt target_9, ExprStmt target_11, ExprStmt target_12, DeclStmt target_13, EqualityOperation target_14
where
func_0(vsun_info_265, vheight_428, target_14, target_0)
and func_1(vbytes_per_line_256, target_14, target_1)
and func_2(vbytes_per_line_256, target_14, target_2)
and func_3(vbytes_per_line_256, target_14, target_3)
and func_4(vbytes_per_line_256, vsun_pixels_269, vheight_428, target_14, target_4)
and func_5(vsun_data_268, target_14, target_5)
and func_6(vbytes_per_line_256, vsun_info_265, vsun_data_268, vsun_pixels_269, vheight_428, target_14, target_6)
and func_7(target_14, func, target_7)
and func_8(target_14, func, target_8)
and func_9(target_14, func, target_9)
and func_11(vsun_data_268, vsun_pixels_269, target_11)
and func_12(vbytes_per_line_256, target_12)
and func_13(target_14, func, target_13)
and func_14(vsun_info_265, target_14)
and vbytes_per_line_256.getType().hasName("size_t")
and vsun_info_265.getType().hasName("SUNInfo")
and vsun_data_268.getType().hasName("unsigned char *")
and vsun_pixels_269.getType().hasName("unsigned char *")
and vheight_428.getType().hasName("size_t")
and vbytes_per_line_256.getParentScope+() = func
and vsun_info_265.getParentScope+() = func
and vsun_data_268.getParentScope+() = func
and vsun_pixels_269.getParentScope+() = func
and vheight_428.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
