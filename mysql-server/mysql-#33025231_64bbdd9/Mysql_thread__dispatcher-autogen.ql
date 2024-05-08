/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Mysql_thread__dispatcher
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/mysqlthreaddispatcher
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/thread/mysql_thread.cc-Mysql_thread__dispatcher mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
	target_0.getExpr().(Literal).getValue()="0"
	and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vparameters_153, FunctionCall target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getQualifier() |
		obj_0.getTarget().getName()="m_body"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and target_1.getTarget().hasName("run")
	and not target_1.getTarget().hasName("execute")
	and target_1.getArgument(0).(VariableAccess).getTarget()=vparameters_153
}

predicate func_3(Function func) {
exists(AddressOfExpr target_3 |
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_trigger_queue"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getArgument(0) instanceof AddressOfExpr
		and obj_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof BreakStmt
	)
	and target_3.getOperand().(VariableAccess).getType().hasName("Mysql_thread_task *")
	and target_3.getEnclosingFunction() = func
)
}

predicate func_6(Variable vparameters_153, AddressOfExpr target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getParent() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_trigger_queue"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof BreakStmt
	)
	and target_6.getOperand().(VariableAccess).getTarget()=vparameters_153
}

predicate func_7(Function func, ThisExpr target_7) {
	target_7.getType() instanceof PointerType
	and target_7.getEnclosingFunction() = func
}

from Function func, Variable vparameters_153, Initializer target_0, FunctionCall target_1, AddressOfExpr target_6, ThisExpr target_7
where
func_0(func, target_0)
and func_1(vparameters_153, target_1)
and not func_3(func)
and func_6(vparameters_153, target_6)
and func_7(func, target_7)
and vparameters_153.getType().hasName("Mysql_thread_body_parameters *")
and vparameters_153.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
