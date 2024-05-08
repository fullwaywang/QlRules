/**
 * @name mysql-server-c08374fb474c633b49177fe45923a344355f384b-Sql_cmd_show_replicas__execute_inner
 * @id cpp/mysql-server/c08374fb474c633b49177fe45923a344355f384b/sqlcmdshowreplicasexecuteinner
 * @description mysql-server-c08374fb474c633b49177fe45923a344355f384b-sql/sql_show.cc-Sql_cmd_show_replicas__execute_inner mysql-#33206343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vthd_635, FunctionCall target_0) {
	target_0.getTarget().hasName("show_slave_hosts")
	and not target_0.getTarget().hasName("show_replicas")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vthd_635
}

from Function func, Parameter vthd_635, FunctionCall target_0
where
func_0(vthd_635, target_0)
and vthd_635.getType().hasName("THD *")
and vthd_635.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
