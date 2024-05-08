/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-buf_LRU_get_free_block
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/buflrugetfreeblock
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/buf/buf0lru.cc-buf_LRU_get_free_block mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmon_value_was_1357, Variable vsrv_print_innodb_monitor, DeclStmt target_5, VariableAccess target_0) {
	exists(AssignExpr obj_0 | obj_0=target_0.getParent() |
		obj_0.getRValue() = target_0
		and obj_0.getLValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
	)
	and target_0.getTarget()=vmon_value_was_1357
}

predicate func_1(Function func) {
exists(FunctionCall target_1 |
	target_1.getTarget().hasName("operator--")
	and target_1.getQualifier().(VariableAccess).getType().hasName("atomic_uint32_t")
	and target_1.getArgument(0).(Literal).getValue()="0"
	and target_1.getEnclosingFunction() = func
)
}

predicate func_2(LogicalAndExpr target_11, Function func) {
exists(IfStmt target_2 |
	exists(BlockStmt obj_0 | obj_0=target_2.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(1) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("operator++")
				and obj_2.getQualifier().(VariableAccess).getType().hasName("atomic_uint32_t")
				and obj_2.getArgument(0).(Literal).getValue()="0"
			)
		)
		and obj_0.getStmt(0) instanceof ExprStmt
	)
	and exists(BlockStmt obj_3 | obj_3=target_2.getParent() |
		exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
			obj_4.getThen().(BlockStmt).getStmt(1)=target_2
			and obj_4.getCondition()=target_11
		)
	)
	and target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
	and target_2.getEnclosingFunction() = func
)
}

/*predicate func_3(Function func) {
exists(FunctionCall target_3 |
	target_3.getTarget().hasName("operator++")
	and target_3.getQualifier().(VariableAccess).getType().hasName("atomic_uint32_t")
	and target_3.getArgument(0).(Literal).getValue()="0"
	and target_3.getEnclosingFunction() = func
)
}

*/
predicate func_4(Variable vstarted_monitor_1358, LogicalAndExpr target_11, ExprStmt target_4) {
	exists(AssignExpr obj_0 | obj_0=target_4.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vstarted_monitor_1358
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(Function func, DeclStmt target_5) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vmon_value_was_1357, Variable vsrv_print_innodb_monitor, AssignExpr target_6) {
	target_6.getLValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
	and target_6.getRValue().(VariableAccess).getTarget()=vmon_value_was_1357
}

predicate func_7(Variable vmon_value_was_1357, Variable vsrv_print_innodb_monitor, AssignExpr target_7) {
	target_7.getLValue().(VariableAccess).getTarget()=vmon_value_was_1357
	and target_7.getRValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
}

predicate func_8(Variable vsrv_print_innodb_monitor, LogicalAndExpr target_11, ExprStmt target_8) {
	exists(AssignExpr obj_0 | obj_0=target_8.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_9(Variable vsrv_monitor_event, LogicalAndExpr target_11, ExprStmt target_9) {
	exists(FunctionCall obj_0 | obj_0=target_9.getExpr() |
		obj_0.getTarget().hasName("os_event_set")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vsrv_monitor_event
	)
	and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_11(Function func, LogicalAndExpr target_11) {
	exists(RelationalOperation obj_0 | obj_0=target_11.getLeftOperand() |
		obj_0.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("ulint")
		and obj_0.getLesserOperand().(Literal).getValue()="20"
	)
	and exists(EqualityOperation obj_1 | obj_1=target_11.getRightOperand() |
		obj_1.getLeftOperand().(VariableAccess).getTarget().getType().hasName("ulint")
		and obj_1.getRightOperand().(VariableAccess).getTarget().getType().hasName("ulint")
	)
	and target_11.getEnclosingFunction() = func
}

from Function func, Variable vsrv_monitor_event, Variable vmon_value_was_1357, Variable vstarted_monitor_1358, Variable vsrv_print_innodb_monitor, VariableAccess target_0, ExprStmt target_4, DeclStmt target_5, AssignExpr target_6, AssignExpr target_7, ExprStmt target_8, ExprStmt target_9, LogicalAndExpr target_11
where
func_0(vmon_value_was_1357, vsrv_print_innodb_monitor, target_5, target_0)
and not func_1(func)
and not func_2(target_11, func)
and func_4(vstarted_monitor_1358, target_11, target_4)
and func_5(func, target_5)
and func_6(vmon_value_was_1357, vsrv_print_innodb_monitor, target_6)
and func_7(vmon_value_was_1357, vsrv_print_innodb_monitor, target_7)
and func_8(vsrv_print_innodb_monitor, target_11, target_8)
and func_9(vsrv_monitor_event, target_11, target_9)
and func_11(func, target_11)
and vsrv_monitor_event.getType().hasName("os_event_t")
and vmon_value_was_1357.getType().hasName("bool")
and vstarted_monitor_1358.getType().hasName("bool")
and vsrv_print_innodb_monitor.getType().hasName("bool")
and not vsrv_monitor_event.getParentScope+() = func
and vmon_value_was_1357.(LocalVariable).getFunction() = func
and vstarted_monitor_1358.(LocalVariable).getFunction() = func
and not vsrv_print_innodb_monitor.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
