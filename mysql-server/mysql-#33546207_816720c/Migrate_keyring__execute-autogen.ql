/**
 * @name mysql-server-816720c1283619c5cb0b25ef7e2f6d04504f21a9-Migrate_keyring__execute
 * @id cpp/mysql-server/816720c1283619c5cb0b25ef7e2f6d04504f21a9/migratekeyringexecute
 * @description mysql-server-816720c1283619c5cb0b25ef7e2f6d04504f21a9-sql/migrate_keyring.cc-Migrate_keyring__execute mysql-#33546207
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_1, Function func) {
exists(ExprStmt target_0 |
	target_0.getExpr().(FunctionCall).getTarget().hasName("ERR_clear_error")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
)
}

predicate func_1(Function func, IfStmt target_1) {
	exists(ExprStmt obj_0 | obj_0=target_1.getThen() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getExpr() |
			obj_1.getTarget().hasName("enable_keyring_operations")
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
	)
	and target_1.getCondition().(VariableAccess).getTarget().getType().hasName("bool")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, IfStmt target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
