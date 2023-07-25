/**
 * @name imagemagick-6e48aa92ff4e6e95424300ecd52a9ea453c19c60-ReadTIFFImage
 * @id cpp/imagemagick/6e48aa92ff4e6e95424300ecd52a9ea453c19c60/ReadTIFFImage
 * @description imagemagick-6e48aa92ff4e6e95424300ecd52a9ea453c19c60-coders/tiff.c-ReadTIFFImage CVE-2016-8677
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vquantum_info_1097, IfStmt target_11, ExprStmt target_12) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vquantum_info_1097
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_11
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vimage_1085, Parameter vimage_info_1071, ExprStmt target_13, RelationalOperation target_5, RelationalOperation target_14) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getThen().(IfStmt).getThen() instanceof BreakStmt
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vimage_1085, Parameter vimage_info_1071, BlockStmt target_15, ExprStmt target_13, RelationalOperation target_5, EqualityOperation target_4) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_3.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_3.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen()=target_15
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vimage_info_1071, IfStmt target_11, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_11
}

predicate func_5(Variable vimage_1085, Parameter vimage_info_1071, BlockStmt target_15, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_5.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_5.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_5.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_5.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_5.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen()=target_15
}

predicate func_6(Variable vimage_1085, Parameter vimage_info_1071, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_6.getThen().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getThen().(IfStmt).getThen().(BreakStmt).toString() = "break;"
}

predicate func_7(Variable vquantum_info_1097, RelationalOperation target_5, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vquantum_info_1097
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyQuantumInfo")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vquantum_info_1097
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_8(RelationalOperation target_5, Function func, BreakStmt target_8) {
		target_8.toString() = "break;"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vquantum_info_1097, VariableAccess target_9) {
		target_9.getTarget()=vquantum_info_1097
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_10(Variable vquantum_info_1097, FunctionCall target_10) {
		target_10.getTarget().hasName("DestroyQuantumInfo")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vquantum_info_1097
}

predicate func_11(IfStmt target_11) {
		target_11.getCondition() instanceof RelationalOperation
		and target_11.getThen() instanceof BlockStmt
}

predicate func_12(Variable vquantum_info_1097, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vquantum_info_1097
		and target_12.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_13(Variable vimage_1085, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="depth"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetImageDepth")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1085
}

predicate func_14(Variable vimage_1085, Parameter vimage_info_1071, RelationalOperation target_14) {
		 (target_14 instanceof GEExpr or target_14 instanceof LEExpr)
		and target_14.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_14.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1085
		and target_14.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_14.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_14.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_14.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_1071
		and target_14.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0) instanceof ExprStmt
		and target_15.getStmt(1) instanceof BreakStmt
}

from Function func, Variable vimage_1085, Variable vquantum_info_1097, Parameter vimage_info_1071, EqualityOperation target_4, RelationalOperation target_5, IfStmt target_6, ExprStmt target_7, BreakStmt target_8, VariableAccess target_9, FunctionCall target_10, IfStmt target_11, ExprStmt target_12, ExprStmt target_13, RelationalOperation target_14, BlockStmt target_15
where
not func_1(vquantum_info_1097, target_11, target_12)
and not func_2(vimage_1085, vimage_info_1071, target_13, target_5, target_14)
and func_4(vimage_info_1071, target_11, target_4)
and func_5(vimage_1085, vimage_info_1071, target_15, target_5)
and func_6(vimage_1085, vimage_info_1071, target_6)
and func_7(vquantum_info_1097, target_5, target_7)
and func_8(target_5, func, target_8)
and func_9(vquantum_info_1097, target_9)
and func_10(vquantum_info_1097, target_10)
and func_11(target_11)
and func_12(vquantum_info_1097, target_12)
and func_13(vimage_1085, target_13)
and func_14(vimage_1085, vimage_info_1071, target_14)
and func_15(target_15)
and vimage_1085.getType().hasName("Image *")
and vquantum_info_1097.getType().hasName("QuantumInfo *")
and vimage_info_1071.getType().hasName("const ImageInfo *")
and vimage_1085.getParentScope+() = func
and vquantum_info_1097.getParentScope+() = func
and vimage_info_1071.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
