/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-georadiusGeneric
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/georadiusGeneric
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/geo.c-georadiusGeneric CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable velelen_650, ExprStmt target_3) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=velelen_650
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable velelen_650, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=velelen_650
}

from Function func, Variable velelen_650, ExprStmt target_3
where
not func_1(velelen_650, target_3)
and func_3(velelen_650, target_3)
and velelen_650.getType().hasName("size_t")
and velelen_650.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
