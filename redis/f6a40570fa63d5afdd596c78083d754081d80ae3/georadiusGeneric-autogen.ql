/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-georadiusGeneric
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/georadiusGeneric
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-georadiusGeneric CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AssignAddExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getRValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vzobj_635, Variable vmaxelelen_638, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("zsetConvertToZiplistIfNeeded")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzobj_635
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmaxelelen_638
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vreturned_items_575, VariableAccess target_4) {
		target_4.getTarget()=vreturned_items_575
}

predicate func_5(Variable vzobj_635, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("zset *")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzobj_635
}

predicate func_6(Variable vzobj_635, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("setKey")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db"
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("client *")
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("robj *")
		and target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vzobj_635
}

predicate func_7(Variable vmaxelelen_638, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmaxelelen_638
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("size_t")
}

from Function func, Variable vreturned_items_575, Variable vzobj_635, Variable vmaxelelen_638, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
vreturned_items_575.getType().hasName("long")
and vzobj_635.getType().hasName("robj *")
and vmaxelelen_638.getType().hasName("size_t")
//and vreturned_items_575.getParentScope+() = func
//and vzobj_635.getParentScope+() = func
//and vmaxelelen_638.getParentScope+() = func
and vreturned_items_575.getAnAccess().getEnclosingFunction() = func
and vzobj_635.getAnAccess().getEnclosingFunction() = func
and vmaxelelen_638.getAnAccess().getEnclosingFunction() = func
and not func_1(func)
and not func_2(vzobj_635, vmaxelelen_638, target_4, target_5, target_6, target_7)
and func_4(vreturned_items_575, target_4)
and func_5(vzobj_635, target_5)
and func_6(vzobj_635, target_6)
and func_7(vmaxelelen_638, target_7)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
