/**
 * @name mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-srv_start_threads
 * @id cpp/mysql-server/abb8ffea2befdd534ea35945d8407aa49a239bc1/srvstartthreads
 * @description mysql-server-abb8ffea2befdd534ea35945d8407aa49a239bc1-storage/innobase/srv/srv0start.cc-srv_start_threads mysql-#33789526
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(ExprStmt target_3, Function func, ExprStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		obj_0.getTarget().hasName("srv_start_state_set")
		and obj_0.getArgument(0) instanceof EnumConstantAccess
	)
	and target_1.getLocation().isBefore(target_3.getLocation())
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, ExprStmt target_2) {
	target_2.getExpr().(FunctionCall).getTarget().hasName("srv_start_state_set")
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Function func, ExprStmt target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_master"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("Srv_threads")
		)
		and obj_0.getTarget().hasName("start")
	)
	and target_3.getEnclosingFunction() = func
}

from Function func, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3
where
func_1(target_3, func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
