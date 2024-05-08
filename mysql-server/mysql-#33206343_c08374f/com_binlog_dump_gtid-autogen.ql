/**
 * @name mysql-server-c08374fb474c633b49177fe45923a344355f384b-com_binlog_dump_gtid
 * @id cpp/mysql-server/c08374fb474c633b49177fe45923a344355f384b/combinlogdumpgtid
 * @description mysql-server-c08374fb474c633b49177fe45923a344355f384b-sql/rpl_source.cc-com_binlog_dump_gtid mysql-#33206343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vthd_925, FunctionCall target_0) {
	target_0.getTarget().hasName("unregister_slave")
	and not target_0.getTarget().hasName("unregister_replica")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vthd_925
	and target_0.getArgument(1).(Literal).getValue()="1"
	and target_0.getArgument(2).(Literal).getValue()="1"
}

from Function func, Parameter vthd_925, FunctionCall target_0
where
func_0(vthd_925, target_0)
and vthd_925.getType().hasName("THD *")
and vthd_925.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
