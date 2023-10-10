/**
 * @name linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-ip6t_do_table
 * @id cpp/linux/57ebd808a97d7c5b1e1afb937c2db22beba3c1f8/ip6t-do-table
 * @description linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-ip6t_do_table NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vverdict_259, Variable vtable_base_261, Variable ve_262, Variable vstackidx_263, Variable vprivate_264, Variable vv_337) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstackidx_263
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stacksize"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprivate_264
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vverdict_259
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtable_base_261
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vv_337
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ip6t_next_entry")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_262
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv6"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_262
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_3(Variable vjumpstack_262, Variable vstackidx_263) {
	exists(PrefixDecrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vstackidx_263
		and target_3.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vjumpstack_262)
}

predicate func_4(Variable vprivate_264) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="underflow"
		and target_4.getQualifier().(VariableAccess).getTarget()=vprivate_264)
}

from Function func, Variable vverdict_259, Variable vtable_base_261, Variable ve_262, Variable vjumpstack_262, Variable vstackidx_263, Variable vprivate_264, Variable vv_337
where
not func_0(vverdict_259, vtable_base_261, ve_262, vstackidx_263, vprivate_264, vv_337)
and vverdict_259.getType().hasName("unsigned int")
and vtable_base_261.getType().hasName("const void *")
and ve_262.getType().hasName("ip6t_entry *")
and vstackidx_263.getType().hasName("unsigned int")
and func_3(vjumpstack_262, vstackidx_263)
and vprivate_264.getType().hasName("const xt_table_info *")
and func_4(vprivate_264)
and vv_337.getType().hasName("int")
and vverdict_259.getParentScope+() = func
and vtable_base_261.getParentScope+() = func
and ve_262.getParentScope+() = func
and vjumpstack_262.getParentScope+() = func
and vstackidx_263.getParentScope+() = func
and vprivate_264.getParentScope+() = func
and vv_337.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
