/**
 * @name imagemagick-aecd0ada163a4d6c769cec178955d5f3e9316f2f-CloneImage
 * @id cpp/imagemagick/aecd0ada163a4d6c769cec178955d5f3e9316f2f/CloneImage
 * @description imagemagick-aecd0ada163a4d6c769cec178955d5f3e9316f2f-MagickCore/image.c-CloneImage CVE-2016-5688
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vclone_image_797, EqualityOperation target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclone_image_797
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclone_image_797
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_4, Function func, EmptyStmt target_1) {
		target_1.toString() = ";"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vclone_image_797, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_image_797
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vclone_image_797, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("CopyMagickMemory")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="colormap"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclone_image_797
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="colormap"
		and target_3.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="64"
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_4.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vclone_image_797, EmptyStmt target_1, EqualityOperation target_2, ExprStmt target_3, EqualityOperation target_4
where
not func_0(vclone_image_797, target_2, target_3)
and func_1(target_4, func, target_1)
and func_2(vclone_image_797, target_2)
and func_3(vclone_image_797, target_3)
and func_4(target_4)
and vclone_image_797.getType().hasName("Image *")
and vclone_image_797.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
