/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-show_modifytable_info
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/show-modifytable-info
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/commands/explain.c-show_modifytable_info CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmtstate_3663, ExprStmt target_3, RelationalOperation target_4) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="ri_RangeTableIndex"
		and target_0.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="resultRelInfo"
		and target_0.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_3663
		and target_0.getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vmtstate_3663, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="resultRelInfo"
		and target_1.getQualifier().(VariableAccess).getTarget()=vmtstate_3663
}

predicate func_2(Parameter vmtstate_3663, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ri_RangeTableIndex"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="resultRelInfo"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_3663
}

predicate func_3(Parameter vmtstate_3663, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("bool")
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="mt_nplans"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_3663
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mt_nplans"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_3663
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="resultRelInfo"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nominalRelation"
		and target_3.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ModifyTable *")
}

predicate func_4(Parameter vmtstate_3663, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="mt_nplans"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_3663
}

from Function func, Parameter vmtstate_3663, PointerFieldAccess target_1, PointerFieldAccess target_2, ExprStmt target_3, RelationalOperation target_4
where
not func_0(vmtstate_3663, target_3, target_4)
and func_1(vmtstate_3663, target_1)
and func_2(vmtstate_3663, target_2)
and func_3(vmtstate_3663, target_3)
and func_4(vmtstate_3663, target_4)
and vmtstate_3663.getType().hasName("ModifyTableState *")
and vmtstate_3663.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
