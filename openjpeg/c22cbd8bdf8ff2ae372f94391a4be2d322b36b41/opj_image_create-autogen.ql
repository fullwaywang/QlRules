/**
 * @name openjpeg-c22cbd8bdf8ff2ae372f94391a4be2d322b36b41-opj_image_create
 * @id cpp/openjpeg/c22cbd8bdf8ff2ae372f94391a4be2d322b36b41/opj-image-create
 * @description openjpeg-c22cbd8bdf8ff2ae372f94391a4be2d322b36b41-src/lib/openjp2/image.c-opj_image_create CVE-2016-9118
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_44, Variable vcomp_61, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="w"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="18446744073709551615"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_image_destroy")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_44
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vimage_44, AddressOfExpr target_1) {
		target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="comps"
		and target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_44
}

predicate func_2(Variable vimage_44, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("opj_image_destroy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_44
}

predicate func_3(Variable vcomp_61, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sgnd"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="sgnd"
}

predicate func_4(Variable vcomp_61, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_calloc")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="w"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="h"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_61
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vimage_44, Variable vcomp_61, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vimage_44, vcomp_61, target_1, target_2, target_3, target_4)
and func_1(vimage_44, target_1)
and func_2(vimage_44, target_2)
and func_3(vcomp_61, target_3)
and func_4(vcomp_61, target_4)
and vimage_44.getType().hasName("opj_image_t *")
and vcomp_61.getType().hasName("opj_image_comp_t *")
and vimage_44.getParentScope+() = func
and vcomp_61.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
