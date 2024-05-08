/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-srv_start
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/srvstart
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/srv/srv0start.cc-srv_start mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, ExprStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		obj_0.getTarget().hasName("srv_start_state_set")
		and obj_0.getArgument(0) instanceof EnumConstantAccess
	)
	and target_1.getFollowingStmt() instanceof DeclStmt
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, ExprStmt target_2) {
	target_2.getExpr().(FunctionCall).getTarget().hasName("srv_start_state_set")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(NotExpr target_4, Function func, ExprStmt target_3) {
	target_3.getExpr().(FunctionCall).getTarget().hasName("srv_start_state_set")
	and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
	and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_5, Function func, NotExpr target_4) {
	target_4.getOperand().(VariableAccess).getTarget().getType().hasName("bool")
	and target_4.getParent().(IfStmt).getThen()=target_5
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, BlockStmt target_5) {
	exists(IfStmt obj_0 | obj_0=target_5.getStmt(0) |
		exists(BlockStmt obj_1 | obj_1=obj_0.getThen() |
			exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
				exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
					obj_3.getLValue().(VariableAccess).getTarget().getType().hasName("bool")
					and obj_3.getRValue().(Literal).getValue()="0"
				)
			)
		)
		and obj_0.getCondition().(VariableAccess).getTarget().getType().hasName("bool")
	)
	and exists(ExprStmt obj_4 | obj_4=target_5.getStmt(1) |
		exists(FunctionCall obj_5 | obj_5=obj_4.getExpr() |
			exists(ValueFieldAccess obj_6 | obj_6=obj_5.getQualifier() |
				obj_6.getTarget().getName()="m_lock_wait_timeout"
				and obj_6.getQualifier().(VariableAccess).getTarget().getType().hasName("Srv_threads")
			)
			and exists(FunctionCall obj_7 | obj_7=obj_5.getArgument(0) |
				obj_7.getTarget().hasName("create_detached_thread")
				and obj_7.getArgument(0).(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				and obj_7.getArgument(1).(Literal).getValue()="0"
			)
			and obj_5.getTarget().hasName("operator=")
		)
	)
	and target_5.getEnclosingFunction() = func
}

from Function func, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, NotExpr target_4, BlockStmt target_5
where
func_1(func, target_1)
and func_2(func, target_2)
and func_3(target_4, func, target_3)
and func_4(target_5, func, target_4)
and func_5(func, target_5)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
