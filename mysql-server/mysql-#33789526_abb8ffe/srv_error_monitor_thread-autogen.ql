/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-srv_error_monitor_thread
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/srverrormonitorthread
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/srv/srv0srv.cc-srv_error_monitor_thread mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsrv_last_monitor_time, Function func, IfStmt target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().hasName("operator-")
			and obj_1.getArgument(0).(FunctionCall).getTarget().hasName("now")
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vsrv_last_monitor_time
		)
		and obj_0.getTarget().hasName("operator>")
		and obj_0.getArgument(1).(ConstructorCall).getArgument(0).(Literal).getValue()="1"
	)
	and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("srv_refresh_innodb_monitor_stats")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

/*predicate func_1(FunctionCall target_2, Function func, ExprStmt target_1) {
	target_1.getExpr().(FunctionCall).getTarget().hasName("srv_refresh_innodb_monitor_stats")
	and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
	and target_1.getEnclosingFunction() = func
}

*/
predicate func_2(Function func, FunctionCall target_2) {
	target_2.getTarget().hasName("operator>")
	and target_2.getArgument(0) instanceof FunctionCall
	and target_2.getArgument(1) instanceof ConstructorCall
	and target_2.getEnclosingFunction() = func
}

from Function func, Variable vsrv_last_monitor_time, IfStmt target_0, FunctionCall target_2
where
func_0(vsrv_last_monitor_time, func, target_0)
and func_2(func, target_2)
and vsrv_last_monitor_time.getType().hasName("time_point")
and not vsrv_last_monitor_time.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
