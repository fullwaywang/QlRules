/**
 * @name mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-dynamic_privilege_services_impl__unregister_privilege
 * @id cpp/mysql-server/b25312b2d666c0589dc688a2d83836d727cb41d0/dynamicprivilegeservicesimplunregisterprivilege
 * @description mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-sql/auth/dynamic_privileges_impl.cc-dynamic_privilege_services_impl__unregister_privilege mysql-#34594035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(FunctionCall target_1, Function func) {
exists(DoStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getThen().(BlockStmt).getStmt(2)=target_0
			and obj_1.getCondition()=target_1
		)
	)
	and target_0.getCondition().(Literal).getValue()="0"
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func, FunctionCall target_1) {
	target_1.getTarget().hasName("is_initialized")
	and target_1.getEnclosingFunction() = func
}

from Function func, FunctionCall target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
