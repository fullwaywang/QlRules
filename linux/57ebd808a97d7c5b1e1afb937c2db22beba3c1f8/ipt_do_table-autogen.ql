/**
 * @name linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-ipt_do_table
 * @id cpp/linux/57ebd808a97d7c5b1e1afb937c2db22beba3c1f8/ipt-do-table
 * @description linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-ipt_do_table NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vverdict_235, Variable vtable_base_237, Variable ve_238, Variable vstackidx_239, Variable vprivate_240, Variable vv_314) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstackidx_239
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stacksize"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprivate_240
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vverdict_235
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtable_base_237
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vv_314
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ipt_next_entry")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_238
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ip"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_238
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_3(Variable vtable_base_237, Variable ve_238, Variable vjumpstack_238, Variable vstackidx_239, Variable vv_314) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vjumpstack_238
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstackidx_239
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_238
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtable_base_237
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vv_314
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ipt_next_entry")
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_238
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ip"
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_238
		and target_3.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2")
}

predicate func_4(Variable vjumpstack_238, Variable vstackidx_239) {
	exists(PrefixDecrExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vstackidx_239
		and target_4.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vjumpstack_238)
}

predicate func_5(Variable vprivate_240) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="underflow"
		and target_5.getQualifier().(VariableAccess).getTarget()=vprivate_240)
}

from Function func, Variable vverdict_235, Variable vtable_base_237, Variable ve_238, Variable vjumpstack_238, Variable vstackidx_239, Variable vprivate_240, Variable vv_314
where
not func_0(vverdict_235, vtable_base_237, ve_238, vstackidx_239, vprivate_240, vv_314)
and func_3(vtable_base_237, ve_238, vjumpstack_238, vstackidx_239, vv_314)
and vverdict_235.getType().hasName("unsigned int")
and vtable_base_237.getType().hasName("const void *")
and ve_238.getType().hasName("ipt_entry *")
and vjumpstack_238.getType().hasName("ipt_entry **")
and vstackidx_239.getType().hasName("unsigned int")
and func_4(vjumpstack_238, vstackidx_239)
and vprivate_240.getType().hasName("const xt_table_info *")
and func_5(vprivate_240)
and vv_314.getType().hasName("int")
and vverdict_235.getParentScope+() = func
and vtable_base_237.getParentScope+() = func
and ve_238.getParentScope+() = func
and vjumpstack_238.getParentScope+() = func
and vstackidx_239.getParentScope+() = func
and vprivate_240.getParentScope+() = func
and vv_314.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
