/**
 * @name mysql-server-72e5d52d0e8d35f153a9ae3dac4c3f42e8be8382-Query_log_event__do_apply_event
 * @id cpp/mysql-server/72e5d52d0e8d35f153a9ae3dac4c3f42e8be8382/querylogeventdoapplyevent
 * @description mysql-server-72e5d52d0e8d35f153a9ae3dac4c3f42e8be8382-sql/log_event.cc-Query_log_event__do_apply_event mysql-#32986721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_2, Function func) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="thd"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_1.getTarget().hasName("get_stmt_da")
		)
		and obj_0.getTarget().hasName("reset_diagnostics_area")
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_2.getLocation())
)
}

predicate func_1(IfStmt target_2, Function func) {
exists(ExprStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="thd"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_1.getTarget().hasName("get_stmt_da")
		)
		and obj_0.getTarget().hasName("reset_statement_cond_count")
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_2.getLocation())
)
}

predicate func_2(Function func, IfStmt target_2) {
	exists(LogicalAndExpr obj_0 | obj_0=target_2.getCondition() |
		exists(EqualityOperation obj_1 | obj_1=obj_0.getLeftOperand() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getLeftOperand() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getArgument(1) |
					obj_3.getTarget().getName()="query"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_2.getTarget().hasName("strcmp")
				and obj_2.getArgument(0).(StringLiteral).getValue()="COMMIT"
			)
			and obj_1.getRightOperand().(Literal).getValue()="0"
		)
		and exists(EqualityOperation obj_4 | obj_4=obj_0.getRightOperand() |
			exists(PointerFieldAccess obj_5 | obj_5=obj_4.getLeftOperand() |
				obj_5.getTarget().getName()="tables_to_lock"
				and obj_5.getQualifier().(VariableAccess).getTarget().getType().hasName("const Relay_log_info *")
			)
			and obj_4.getRightOperand().(Literal).getValue()="0"
		)
	)
	and exists(BlockStmt obj_6 | obj_6=target_2.getThen() |
		exists(IfStmt obj_7 | obj_7=obj_6.getStmt(2) |
			exists(AssignExpr obj_8 | obj_8=obj_7.getCondition() |
				exists(FunctionCall obj_9 | obj_9=obj_8.getRValue() |
					exists(PointerFieldAccess obj_10 | obj_10=obj_9.getArgument(1) |
						obj_10.getTarget().getName()="thd"
						and obj_10.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_9.getTarget().hasName("rows_event_stmt_cleanup")
					and obj_9.getArgument(0).(VariableAccess).getTarget().getType().hasName("const Relay_log_info *")
				)
				and obj_8.getLValue().(VariableAccess).getTarget().getType().hasName("int")
			)
			and exists(BlockStmt obj_11 | obj_11=obj_7.getThen() |
				exists(ExprStmt obj_12 | obj_12=obj_11.getStmt(0) |
					exists(FunctionCall obj_13 | obj_13=obj_12.getExpr() |
						obj_13.getTarget().hasName("report")
						and obj_13.getQualifier().(VariableAccess).getTarget().getType().hasName("const Relay_log_info *")
						and obj_13.getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
						and obj_13.getArgument(2).(StringLiteral).getValue()="Error in cleaning up after an event preceding the commit; the group log file/position: %s %s"
						and obj_13.getArgument(3).(FunctionCall).getTarget().hasName("get_group_master_log_name_info")
						and obj_13.getArgument(4).(FunctionCall).getTarget().hasName("llstr")
					)
				)
			)
		)
	)
	and exists(BlockStmt obj_14 | obj_14=target_2.getElse() |
		exists(ExprStmt obj_15 | obj_15=obj_14.getStmt(0) |
			exists(FunctionCall obj_16 | obj_16=obj_15.getExpr() |
				exists(PointerFieldAccess obj_17 | obj_17=obj_16.getArgument(0) |
					obj_17.getTarget().getName()="thd"
					and obj_17.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_16.getTarget().hasName("slave_close_thread_tables")
				and obj_16.getQualifier().(VariableAccess).getTarget().getType().hasName("const Relay_log_info *")
			)
		)
	)
	and target_2.getEnclosingFunction() = func
}

from Function func, IfStmt target_2
where
not func_0(target_2, func)
and not func_1(target_2, func)
and func_2(func, target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
