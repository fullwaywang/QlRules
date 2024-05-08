/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Mysql_thread__~Mysql_thread
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/mysqlthread~mysqlthread
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/thread/mysql_thread.cc-Mysql_thread__~Mysql_thread mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
	target_0.getExpr().(Literal).getValue()="0"
	and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_3(Function func) {
exists(AddressOfExpr target_3 |
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="m_trigger_queue"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_2.getTarget().hasName("pop")
				and obj_2.getArgument(0) instanceof AddressOfExpr
			)
		)
	)
	and target_3.getOperand().(VariableAccess).getType().hasName("Mysql_thread_task *")
	and target_3.getEnclosingFunction() = func
)
}

predicate func_6(Variable vparameters_56, AddressOfExpr target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="m_trigger_queue"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_2.getTarget().hasName("pop")
			)
		)
	)
	and target_6.getOperand().(VariableAccess).getTarget()=vparameters_56
}

from Function func, Variable vparameters_56, Initializer target_0, AddressOfExpr target_6
where
func_0(func, target_0)
and not func_3(func)
and func_6(vparameters_56, target_6)
and vparameters_56.getType().hasName("Mysql_thread_body_parameters *")
and vparameters_56.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
