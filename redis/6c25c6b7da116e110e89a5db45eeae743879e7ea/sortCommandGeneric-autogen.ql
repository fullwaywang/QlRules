/**
 * @name redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-sortCommandGeneric
 * @id cpp/redis/6c25c6b7da116e110e89a5db45eeae743879e7ea/sortCommandGeneric
 * @description redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-sortCommandGeneric CVE-2022-35977
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlimit_start_193, AddressOfExpr target_9) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_start_193
		and target_0.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_0.getThen().(VariableAccess).getTarget()=vlimit_start_193
		and target_0.getElse() instanceof Literal
		and target_0.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vlimit_start_193
		and target_0.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlimit_start_193, ExprStmt target_10) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_start_193
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getThen().(VariableAccess).getTarget()=vlimit_start_193
		and target_2.getElse().(Literal).getValue()="0"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vlimit_count_193, Variable vvectorlen_194, AddressOfExpr target_11, ExprStmt target_12, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlimit_count_193
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_count_193
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_count_193
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-1"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vvectorlen_194
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_count_193
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vlimit_count_193
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-1"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vvectorlen_194
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_4)
		and target_11.getOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vlimit_start_193, VariableAccess target_5) {
		target_5.getTarget()=vlimit_start_193
		and target_5.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vlimit_start_193, VariableAccess target_8) {
		target_8.getTarget()=vlimit_start_193
}

predicate func_9(Variable vlimit_start_193, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vlimit_start_193
}

predicate func_10(Variable vlimit_start_193, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("long")
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_start_193
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen() instanceof Literal
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vlimit_start_193
}

predicate func_11(Variable vlimit_count_193, AddressOfExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vlimit_count_193
}

predicate func_12(Variable vlimit_count_193, Variable vvectorlen_194, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("long")
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_count_193
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vvectorlen_194
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("long")
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlimit_count_193
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vlimit_start_193, Variable vlimit_count_193, Variable vvectorlen_194, VariableAccess target_5, VariableAccess target_8, AddressOfExpr target_9, ExprStmt target_10, AddressOfExpr target_11, ExprStmt target_12
where
not func_0(vlimit_start_193, target_9)
and not func_2(vlimit_start_193, target_10)
and not func_4(vlimit_count_193, vvectorlen_194, target_11, target_12, func)
and func_5(vlimit_start_193, target_5)
and func_8(vlimit_start_193, target_8)
and func_9(vlimit_start_193, target_9)
and func_10(vlimit_start_193, target_10)
and func_11(vlimit_count_193, target_11)
and func_12(vlimit_count_193, vvectorlen_194, target_12)
and vlimit_start_193.getType().hasName("long")
and vlimit_count_193.getType().hasName("long")
and vvectorlen_194.getType().hasName("int")
and vlimit_start_193.getParentScope+() = func
and vlimit_count_193.getParentScope+() = func
and vvectorlen_194.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
