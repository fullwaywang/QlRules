/**
 * @name imagemagick-a2e1064f288a353bc5fef7f79ccb7683759e775c-load_tile
 * @id cpp/imagemagick/a2e1064f288a353bc5fef7f79ccb7683759e775c/load-tile
 * @description imagemagick-a2e1064f288a353bc5fef7f79ccb7683759e775c-coders/xcf.c-load_tile CVE-2016-7529
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtile_image_327, Parameter vdata_length_328, RelationalOperation target_2, ExprStmt target_3) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_length_328
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_image_327
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_image_327
		and target_0.getThen().(VariableAccess).getTarget()=vdata_length_328
		and target_0.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_image_327
		and target_0.getElse().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getElse().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_image_327
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_length_328
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_length_328, VariableAccess target_1) {
		target_1.getTarget()=vdata_length_328
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
}

predicate func_2(Parameter vtile_image_327, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtile_image_327
}

predicate func_3(Parameter vdata_length_328, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_length_328
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
}

from Function func, Parameter vtile_image_327, Parameter vdata_length_328, VariableAccess target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(vtile_image_327, vdata_length_328, target_2, target_3)
and func_1(vdata_length_328, target_1)
and func_2(vtile_image_327, target_2)
and func_3(vdata_length_328, target_3)
and vtile_image_327.getType().hasName("Image *")
and vdata_length_328.getType().hasName("size_t")
and vtile_image_327.getParentScope+() = func
and vdata_length_328.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
