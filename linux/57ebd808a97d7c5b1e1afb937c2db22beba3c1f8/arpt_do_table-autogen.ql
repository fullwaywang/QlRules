/**
 * @name linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-arpt_do_table
 * @id cpp/linux/57ebd808a97d7c5b1e1afb937c2db22beba3c1f8/arpt-do-table
 * @description linux-57ebd808a97d7c5b1e1afb937c2db22beba3c1f8-arpt_do_table 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vverdict_187, Variable ve_189, Variable vtable_base_191, Variable vstackidx_192, Variable vprivate_193, Variable vv_235) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstackidx_192
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stacksize"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprivate_193
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vverdict_187
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtable_base_191
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vv_235
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("arpt_next_entry")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_189)
}

predicate func_3(Variable vjumpstack_189, Variable vstackidx_192) {
	exists(PrefixDecrExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vstackidx_192
		and target_3.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vjumpstack_189)
}

predicate func_4(Variable vprivate_193) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="underflow"
		and target_4.getQualifier().(VariableAccess).getTarget()=vprivate_193)
}

from Function func, Variable vverdict_187, Variable ve_189, Variable vjumpstack_189, Variable vtable_base_191, Variable vstackidx_192, Variable vprivate_193, Variable vv_235
where
not func_0(vverdict_187, ve_189, vtable_base_191, vstackidx_192, vprivate_193, vv_235)
and vverdict_187.getType().hasName("unsigned int")
and ve_189.getType().hasName("arpt_entry *")
and vtable_base_191.getType().hasName("const void *")
and vstackidx_192.getType().hasName("unsigned int")
and func_3(vjumpstack_189, vstackidx_192)
and vprivate_193.getType().hasName("const xt_table_info *")
and func_4(vprivate_193)
and vv_235.getType().hasName("int")
and vverdict_187.getParentScope+() = func
and ve_189.getParentScope+() = func
and vjumpstack_189.getParentScope+() = func
and vtable_base_191.getParentScope+() = func
and vstackidx_192.getParentScope+() = func
and vprivate_193.getParentScope+() = func
and vv_235.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
