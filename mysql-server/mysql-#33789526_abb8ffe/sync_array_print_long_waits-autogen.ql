/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-sync_array_print_long_waits
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/syncarrayprintlongwaits
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/sync/sync0arr.cc-sync_array_print_long_waits mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
exists(FunctionCall target_0 |
	target_0.getTarget().hasName("operator++")
	and target_0.getQualifier().(VariableAccess).getType().hasName("atomic_uint32_t")
	and target_0.getArgument(0).(Literal).getValue()="0"
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func) {
exists(FunctionCall target_1 |
	target_1.getTarget().hasName("operator--")
	and target_1.getQualifier().(VariableAccess).getType().hasName("atomic_uint32_t")
	and target_1.getArgument(0).(Literal).getValue()="0"
	and target_1.getEnclosingFunction() = func
)
}

predicate func_2(VariableAccess target_5, Function func, DeclStmt target_2) {
	target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vsrv_print_innodb_monitor, AssignExpr target_3) {
	target_3.getLValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
	and target_3.getRValue().(Literal).getValue()="1"
}

predicate func_4(Variable vold_val_878, Variable vsrv_print_innodb_monitor, AssignExpr target_4) {
	target_4.getLValue().(VariableAccess).getTarget()=vsrv_print_innodb_monitor
	and target_4.getRValue().(VariableAccess).getTarget()=vold_val_878
}

predicate func_5(Variable vnoticed_859, VariableAccess target_5) {
	target_5.getTarget()=vnoticed_859
}

from Function func, Variable vnoticed_859, Variable vold_val_878, Variable vsrv_print_innodb_monitor, DeclStmt target_2, AssignExpr target_3, AssignExpr target_4, VariableAccess target_5
where
not func_0(func)
and not func_1(func)
and func_2(target_5, func, target_2)
and func_3(vsrv_print_innodb_monitor, target_3)
and func_4(vold_val_878, vsrv_print_innodb_monitor, target_4)
and func_5(vnoticed_859, target_5)
and vnoticed_859.getType().hasName("bool")
and vold_val_878.getType().hasName("bool")
and vsrv_print_innodb_monitor.getType().hasName("bool")
and vnoticed_859.(LocalVariable).getFunction() = func
and vold_val_878.(LocalVariable).getFunction() = func
and not vsrv_print_innodb_monitor.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
