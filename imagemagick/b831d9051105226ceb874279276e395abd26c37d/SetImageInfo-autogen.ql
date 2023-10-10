/**
 * @name imagemagick-b831d9051105226ceb874279276e395abd26c37d-SetImageInfo
 * @id cpp/imagemagick/b831d9051105226ceb874279276e395abd26c37d/SetImageInfo
 * @description imagemagick-b831d9051105226ceb874279276e395abd26c37d-MagickCore/image.c-SetImageInfo CVE-2016-3715
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_2490, EqualityOperation target_4, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="temporary"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_2490
		and target_0.getParent().(IfStmt).getCondition()=target_4
}

predicate func_1(Parameter vimage_info_2490, EqualityOperation target_4, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="affirm"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_2490
		and target_1.getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vmagic_2495, EqualityOperation target_5, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("LocaleCompare")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmagic_2495
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="EPHEMERAL"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen() instanceof ExprStmt
		and target_3.getElse() instanceof ExprStmt
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand() instanceof FunctionCall
		and target_4.getAnOperand() instanceof Literal
}

predicate func_5(Variable vmagic_2495, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("IsMagickConflict")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmagic_2495
}

from Function func, Variable vmagic_2495, Parameter vimage_info_2490, ExprStmt target_0, ExprStmt target_1, IfStmt target_3, EqualityOperation target_4, EqualityOperation target_5
where
func_0(vimage_info_2490, target_4, target_0)
and func_1(vimage_info_2490, target_4, target_1)
and func_3(vmagic_2495, target_5, target_3)
and func_4(target_4)
and func_5(vmagic_2495, target_5)
and vmagic_2495.getType().hasName("char[4096]")
and vimage_info_2490.getType().hasName("ImageInfo *")
and vmagic_2495.getParentScope+() = func
and vimage_info_2490.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
