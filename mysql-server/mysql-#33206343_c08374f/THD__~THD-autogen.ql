/**
 * @name mysql-server-c08374fb474c633b49177fe45923a344355f384b-THD__~THD
 * @id cpp/mysql-server/c08374fb474c633b49177fe45923a344355f384b/thd~thd
 * @description mysql-server-c08374fb474c633b49177fe45923a344355f384b-sql/sql_class.cc-THD__~THD mysql-#33206343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
	target_0.getTarget().hasName("unregister_slave")
	and not target_0.getTarget().hasName("unregister_replica")
	and target_0.getArgument(0).(ThisExpr).getType() instanceof PointerType
	and target_0.getArgument(1).(Literal).getValue()="1"
	and target_0.getArgument(2).(Literal).getValue()="1"
	and target_0.getEnclosingFunction() = func
}

from Function func, FunctionCall target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
