/**
 * @name imagemagick-256825d4eb33dc301496710d15cf5a7ae924088b-TIFFWritePhotoshopLayers
 * @id cpp/imagemagick/256825d4eb33dc301496710d15cf5a7ae924088b/TIFFWritePhotoshopLayers
 * @description imagemagick-256825d4eb33dc301496710d15cf5a7ae924088b-coders/tiff.c-TIFFWritePhotoshopLayers CVE-2018-16641
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbase_image_3101, EqualityOperation target_3, EqualityOperation target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_image_3101
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_image_3101
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbase_image_3101, EqualityOperation target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_image_3101
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_image_3101
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_2(Variable vbase_image_3101, EqualityOperation target_6, ExprStmt target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_image_3101
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_image_3101
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vbase_image_3101, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vbase_image_3101
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(EqualityOperation target_6) {
		target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vbase_image_3101, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("DestroyBlob")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbase_image_3101
}

from Function func, Variable vbase_image_3101, EqualityOperation target_3, EqualityOperation target_4, EqualityOperation target_5, EqualityOperation target_6, ExprStmt target_7
where
not func_0(vbase_image_3101, target_3, target_4)
and not func_1(vbase_image_3101, target_5)
and not func_2(vbase_image_3101, target_6, target_7)
and func_3(target_3)
and func_4(vbase_image_3101, target_4)
and func_5(target_5)
and func_6(target_6)
and func_7(vbase_image_3101, target_7)
and vbase_image_3101.getType().hasName("Image *")
and vbase_image_3101.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
