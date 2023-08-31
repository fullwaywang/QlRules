/**
 * @name postgresql-c33c42362256382ed398df9dcda559cd547c68a7-calc_rangesel
 * @id cpp/postgresql/c33c42362256382ed398df9dcda559cd547c68a7/calc-rangesel
 * @description postgresql-c33c42362256382ed398df9dcda559cd547c68a7-src/backend/utils/adt/rangetypes_selfuncs.c-calc_rangesel CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnumbers_241, Variable vnnumbers_242, Parameter vvardata_227, FunctionCall target_1, ExprStmt target_2, EqualityOperation target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("free_attstatsslot")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnumbers_241
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnnumbers_242
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vnumbers_241, Variable vnnumbers_242, Parameter vvardata_227, FunctionCall target_1) {
		target_1.getTarget().hasName("get_attstatsslot")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getArgument(3).(Literal).getValue()="6"
		and target_1.getArgument(4).(Literal).getValue()="0"
		and target_1.getArgument(5).(Literal).getValue()="0"
		and target_1.getArgument(6).(Literal).getValue()="0"
		and target_1.getArgument(7).(Literal).getValue()="0"
		and target_1.getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnumbers_241
		and target_1.getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnnumbers_242
}

predicate func_2(Variable vnumbers_241, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("float4")
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnumbers_241
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Variable vnnumbers_242, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vnnumbers_242
		and target_3.getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Parameter vvardata_227, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calc_hist_selectivity")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TypeCacheEntry *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvardata_227
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("RangeType *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("Oid")
}

from Function func, Variable vnumbers_241, Variable vnnumbers_242, Parameter vvardata_227, FunctionCall target_1, ExprStmt target_2, EqualityOperation target_3, ExprStmt target_4
where
not func_0(vnumbers_241, vnnumbers_242, vvardata_227, target_1, target_2, target_3, target_4)
and func_1(vnumbers_241, vnnumbers_242, vvardata_227, target_1)
and func_2(vnumbers_241, target_2)
and func_3(vnnumbers_242, target_3)
and func_4(vvardata_227, target_4)
and vnumbers_241.getType().hasName("float4 *")
and vnnumbers_242.getType().hasName("int")
and vvardata_227.getType().hasName("VariableStatData *")
and vnumbers_241.(LocalVariable).getFunction() = func
and vnnumbers_242.(LocalVariable).getFunction() = func
and vvardata_227.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
