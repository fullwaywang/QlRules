/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-zunionInterGenericCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/zunionInterGenericCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-zunionInterGenericCommand CVE-2021-32627 CVE-2021-32628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vtmp_2182, EqualityOperation target_4, ExprStmt target_5, RelationalOperation target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_2182
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtmp_2182, NotExpr target_7, ExprStmt target_8, RelationalOperation target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("sdslen")
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_2182
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getAnOperand().(VariableAccess).getTarget().getType().hasName("long")
}

predicate func_5(Variable vtmp_2182, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("dictAdd")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("zset *")
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtmp_2182
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="score"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("zskiplistNode *")
}

predicate func_6(Variable vtmp_2182, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_6.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_2182
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

predicate func_7(NotExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget().getType().hasName("dictEntry *")
}

predicate func_8(Variable vtmp_2182, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_2182
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zuiNewSdsFromValue")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("zsetopval")
}

predicate func_9(Variable vtmp_2182, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_9.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_2182
		and target_9.getLesserOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

from Function func, Variable vtmp_2182, EqualityOperation target_4, ExprStmt target_5, RelationalOperation target_6, NotExpr target_7, ExprStmt target_8, RelationalOperation target_9
where
not func_1(vtmp_2182, target_4, target_5, target_6)
and not func_2(vtmp_2182, target_7, target_8, target_9)
and func_4(target_4)
and func_5(vtmp_2182, target_5)
and func_6(vtmp_2182, target_6)
and func_7(target_7)
and func_8(vtmp_2182, target_8)
and func_9(vtmp_2182, target_9)
and vtmp_2182.getType().hasName("sds")
and vtmp_2182.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
