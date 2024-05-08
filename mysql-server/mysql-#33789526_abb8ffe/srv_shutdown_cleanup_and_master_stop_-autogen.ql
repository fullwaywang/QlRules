/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-srv_shutdown_cleanup_and_master_stop_
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/srvshutdowncleanupandmasterstop
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/sync/sync0arr.cc-srv_shutdown_cleanup_and_master_stop_ mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ut_dbg_assertion_failed")
				and obj_2.getArgument(0).(StringLiteral).getValue()="srv_shutdown_state.load() == SRV_SHUTDOWN_DD"
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/srv/srv0start.cc"
			)
		)
	)
	and target_0.getValue()="3319"
	and not target_0.getValue()="3344"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ut_dbg_assertion_failed")
				and obj_2.getArgument(0).(StringLiteral).getValue()="thread_info.m_wait_on_state <= max_wait_on_state"
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/srv/srv0start.cc"
			)
		)
	)
	and target_1.getValue()="3378"
	and not target_1.getValue()="3365"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ut_dbg_assertion_failed")
				and obj_2.getArgument(0).(StringLiteral).getValue()="srv_shutdown_state.load() == SRV_SHUTDOWN_MASTER_STOP"
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/srv/srv0start.cc"
			)
		)
	)
	and target_2.getValue()="3402"
	and not target_2.getValue()="3389"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, DeclStmt target_3) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Function func, DeclStmt target_4) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

from Function func, Literal target_0, Literal target_1, Literal target_2, DeclStmt target_3, DeclStmt target_4
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
