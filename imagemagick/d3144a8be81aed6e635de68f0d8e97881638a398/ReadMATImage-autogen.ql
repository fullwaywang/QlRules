/**
 * @name imagemagick-d3144a8be81aed6e635de68f0d8e97881638a398-ReadMATImage
 * @id cpp/imagemagick/d3144a8be81aed6e635de68f0d8e97881638a398/ReadMATImage
 * @description imagemagick-d3144a8be81aed6e635de68f0d8e97881638a398-coders/mat.c-ReadMATImage CVE-2017-18029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_850, Variable vimage2_850, EqualityOperation target_1, IfStmt target_0) {
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_850
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage2_850
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage2_850
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage2_850
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage2_850
		and target_0.getParent().(IfStmt).getCondition()=target_1
}

predicate func_1(Variable vimage_850, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vimage_850
		and target_1.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vimage_850, Variable vimage2_850, IfStmt target_0, EqualityOperation target_1
where
func_0(vimage_850, vimage2_850, target_1, target_0)
and func_1(vimage_850, target_1)
and vimage_850.getType().hasName("Image *")
and vimage2_850.getType().hasName("Image *")
and vimage_850.getParentScope+() = func
and vimage2_850.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
