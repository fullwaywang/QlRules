/**
 * @name linux-f85daf0e725358be78dfd208dea5fd665d8cb901-xfrm_expand_policies
 * @id cpp/linux/f85daf0e725358be78dfd208dea5fd665d8cb901/xfrm-expand-policies
 * @description linux-f85daf0e725358be78dfd208dea5fd665d8cb901-xfrm_expand_policies 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnum_pols_2672, Parameter vpols_2671) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnum_pols_2672
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_2(Parameter vpols_2671) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_3(Parameter vfamily_2670, Parameter vpols_2671, Parameter vfl_2670) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xfrm_policy_lookup_bytype")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("xp_net")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfl_2670
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfamily_2670
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="if_id"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="action"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_4(Parameter vnum_pols_2672, Parameter vpols_2671) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("xfrm_pols_put")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpols_2671
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnum_pols_2672
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_5(Parameter vpols_2671) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_5.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_5.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_6(Parameter vnum_pols_2672, Parameter vpols_2671) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnum_pols_2672
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_7(Parameter vnum_xfrms_2672, Parameter vpols_2671) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnum_xfrms_2672
		and target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="xfrm_nr"
		and target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_7.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpols_2671
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_8(Parameter vnum_pols_2672) {
	exists(PointerDereferenceExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vnum_pols_2672
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vnum_pols_2672, Parameter vnum_xfrms_2672, Parameter vfamily_2670, Parameter vpols_2671, Parameter vfl_2670
where
not func_0(vnum_pols_2672, vpols_2671)
and func_2(vpols_2671)
and func_3(vfamily_2670, vpols_2671, vfl_2670)
and func_4(vnum_pols_2672, vpols_2671)
and func_5(vpols_2671)
and func_6(vnum_pols_2672, vpols_2671)
and func_7(vnum_xfrms_2672, vpols_2671)
and vnum_pols_2672.getType().hasName("int *")
and func_8(vnum_pols_2672)
and vnum_xfrms_2672.getType().hasName("int *")
and vfamily_2670.getType().hasName("u16")
and vpols_2671.getType().hasName("xfrm_policy **")
and vfl_2670.getType().hasName("const flowi *")
and vnum_pols_2672.getParentScope+() = func
and vnum_xfrms_2672.getParentScope+() = func
and vfamily_2670.getParentScope+() = func
and vpols_2671.getParentScope+() = func
and vfl_2670.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
