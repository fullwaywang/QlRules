/**
 * @name freerdp-9fee4ae076b1ec97b97efb79ece08d1dab4df29a-region16_union_rect
 * @id cpp/freerdp/9fee4ae076b1ec97b97efb79ece08d1dab4df29a/region16-union-rect
 * @description freerdp-9fee4ae076b1ec97b97efb79ece08d1dab4df29a-libfreerdp/codec/region.c-region16_union_rect CVE-2019-17177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vnewItems_491, ExprStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("REGION16_DATA *")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewItems_491
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_1)
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vnewItems_491, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewItems_491
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("REGION16_DATA *")
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vdst_486, Variable vnewItems_491, LogicalAndExpr target_6, NotExpr target_7, ExprStmt target_8, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_486
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnewItems_491
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_3)
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdst_486, Variable vnewItems_491, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="data"
		and target_4.getQualifier().(VariableAccess).getTarget()=vdst_486
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewItems_491
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewItems_491
}

predicate func_5(Parameter vdst_486, Variable vnewItems_491, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_486
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewItems_491
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewItems_491
}

predicate func_6(Parameter vdst_486, LogicalAndExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdst_486
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
}

predicate func_7(Parameter vdst_486, NotExpr target_7) {
		target_7.getOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_486
}

predicate func_8(Variable vnewItems_491, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewItems_491
}

from Function func, Parameter vdst_486, Variable vnewItems_491, PointerFieldAccess target_4, ExprStmt target_5, LogicalAndExpr target_6, NotExpr target_7, ExprStmt target_8
where
not func_1(vnewItems_491, target_5, func)
and not func_2(vnewItems_491, func)
and not func_3(vdst_486, vnewItems_491, target_6, target_7, target_8, func)
and func_4(vdst_486, vnewItems_491, target_4)
and func_5(vdst_486, vnewItems_491, target_5)
and func_6(vdst_486, target_6)
and func_7(vdst_486, target_7)
and func_8(vnewItems_491, target_8)
and vdst_486.getType().hasName("REGION16 *")
and vnewItems_491.getType().hasName("REGION16_DATA *")
and vdst_486.getParentScope+() = func
and vnewItems_491.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
