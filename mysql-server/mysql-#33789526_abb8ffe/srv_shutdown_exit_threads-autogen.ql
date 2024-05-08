/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-srv_shutdown_exit_threads
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/srvshutdownexitthreads
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/srv/srv0start.cc-srv_shutdown_exit_threads mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func, FunctionCall target_2) {
	target_2.getTarget().hasName("srv_wake_master_thread")
	and not target_2.getTarget().hasName("srv_purge_wakeup")
	and target_2.getEnclosingFunction() = func
}

predicate func_5(Variable vlock_sys, FunctionCall target_5) {
	exists(PointerFieldAccess obj_0 | obj_0=target_5.getArgument(0) |
		obj_0.getTarget().getName()="timeout_event"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlock_sys
	)
	and target_5.getTarget().hasName("os_event_set")
	and not target_5.getTarget().hasName("operator()")
}

predicate func_6(IfStmt target_12, Function func) {
exists(RangeBasedForStmt target_6 |
	exists(EqualityOperation obj_0 | obj_0=target_6.getCondition() |
		obj_0.getLeftOperand().(VariableAccess).getType().hasName("const Thread_to_stop *")
		and obj_0.getRightOperand().(VariableAccess).getType().hasName("const Thread_to_stop *")
	)
	and exists(BlockStmt obj_1 | obj_1=target_6.getStmt() |
		exists(IfStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getCondition() |
				exists(ReferenceFieldAccess obj_4 | obj_4=obj_3.getArgument(0) |
					obj_4.getTarget().getName()="m_thread"
					and obj_4.getQualifier().(VariableAccess).getType().hasName("const Thread_to_stop &")
				)
				and obj_3.getTarget().hasName("srv_thread_is_active")
			)
			and exists(BlockStmt obj_5 | obj_5=obj_2.getThen() |
				exists(ExprStmt obj_6 | obj_6=obj_5.getStmt(0) |
					exists(FunctionCall obj_7 | obj_7=obj_6.getExpr() |
						obj_7.getTarget().hasName("operator()")
						and obj_7.getQualifier().(ReferenceFieldAccess).getTarget().getName()="m_notify"
					)
				)
			)
		)
	)
	and target_6.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getType().hasName("const Thread_to_stop *")
	and target_6.getLocation().isBefore(target_12.getLocation())
	and target_6.getEnclosingFunction() = func
)
}

/*predicate func_7(BlockStmt target_13, Function func) {
exists(FunctionCall target_7 |
	exists(ReferenceFieldAccess obj_0 | obj_0=target_7.getArgument(0) |
		obj_0.getTarget().getName()="m_thread"
		and obj_0.getQualifier().(VariableAccess).getType().hasName("const Thread_to_stop &")
	)
	and target_7.getTarget().hasName("srv_thread_is_active")
	and target_7.getParent().(IfStmt).getThen()=target_13
	and target_7.getEnclosingFunction() = func
)
}

*/
/*predicate func_8(Function func) {
exists(ReferenceFieldAccess target_8 |
	target_8.getTarget().getName()="m_notify"
	and target_8.getQualifier().(VariableAccess).getType().hasName("const Thread_to_stop &")
	and target_8.getEnclosingFunction() = func
)
}

*/
predicate func_9(Variable vsrv_read_only_mode, BlockStmt target_13, NotExpr target_9) {
	target_9.getOperand().(VariableAccess).getTarget()=vsrv_read_only_mode
	and target_9.getParent().(IfStmt).getThen()=target_13
}

predicate func_10(Variable vlock_sys, VariableAccess target_10) {
	target_10.getTarget()=vlock_sys
	and target_10.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_11(NotExpr target_9, Function func, IfStmt target_11) {
	exists(FunctionCall obj_0 | obj_0=target_11.getCondition() |
		obj_0.getTarget().hasName("srv_start_state_is_set")
		and obj_0.getArgument(0) instanceof EnumConstantAccess
	)
	and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("srv_purge_wakeup")
	and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
	and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, IfStmt target_12) {
	exists(BlockStmt obj_0 | obj_0=target_12.getThen() |
		exists(IfStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getCondition() |
				obj_2.getTarget().hasName("srv_start_state_is_set")
				and obj_2.getArgument(0) instanceof EnumConstantAccess
			)
			and obj_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		)
		and exists(IfStmt obj_3 | obj_3=obj_0.getStmt(1) |
			exists(FunctionCall obj_4 | obj_4=obj_3.getCondition() |
				obj_4.getTarget().hasName("srv_start_state_is_set")
				and obj_4.getArgument(0) instanceof EnumConstantAccess
			)
			and obj_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		)
	)
	and target_12.getCondition() instanceof NotExpr
	and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, BlockStmt target_13) {
	exists(IfStmt obj_0 | obj_0=target_13.getStmt(0) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getCondition() |
			obj_1.getTarget().hasName("srv_start_state_is_set")
			and obj_1.getArgument(0) instanceof EnumConstantAccess
		)
		and obj_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
	)
	and exists(IfStmt obj_2 | obj_2=target_13.getStmt(1) |
		exists(FunctionCall obj_3 | obj_3=obj_2.getCondition() |
			obj_3.getTarget().hasName("srv_start_state_is_set")
			and obj_3.getArgument(0) instanceof EnumConstantAccess
		)
		and obj_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
	)
	and target_13.getEnclosingFunction() = func
}

from Function func, Variable vsrv_read_only_mode, Variable vlock_sys, FunctionCall target_2, FunctionCall target_5, NotExpr target_9, VariableAccess target_10, IfStmt target_11, IfStmt target_12, BlockStmt target_13
where
func_2(func, target_2)
and func_5(vlock_sys, target_5)
and not func_6(target_12, func)
and func_9(vsrv_read_only_mode, target_13, target_9)
and func_10(vlock_sys, target_10)
and func_11(target_9, func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and vsrv_read_only_mode.getType().hasName("bool")
and vlock_sys.getType().hasName("lock_sys_t *")
and not vsrv_read_only_mode.getParentScope+() = func
and not vlock_sys.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
