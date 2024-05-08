/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Mysql_thread__initialize
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/mysqlthreadinitialize
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/thread/mysql_thread.cc-Mysql_thread__initialize mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
exists(PointerFieldAccess target_0 |
	target_0.getTarget().getName()="m_thread_key"
	and target_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Variable vkey_GR_THD_mysql_thread, BlockStmt target_2, VariableAccess target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(AddressOfExpr obj_1 | obj_1=obj_0.getArgument(2) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getOperand() |
				obj_2.getTarget().getName()="m_pthd"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
		)
		and obj_0.getArgument(1).(Literal).getValue()="0"
		and obj_0.getArgument(3).(FunctionCall).getTarget().hasName("get_connection_attrib")
		and obj_0.getArgument(5).(ThisExpr).getType() instanceof PointerType
		and obj_0.getParent().(IfStmt).getThen()=target_2
	)
	and target_1.getTarget()=vkey_GR_THD_mysql_thread
}

predicate func_2(Function func, BlockStmt target_2) {
	exists(ExprStmt obj_0 | obj_0=target_2.getStmt(0) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getExpr() |
			exists(AddressOfExpr obj_2 | obj_2=obj_1.getArgument(0) |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getOperand() |
					obj_3.getTarget().getName()="m_run_lock"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
			)
			and obj_1.getTarget().hasName("inline_mysql_mutex_unlock")
			and obj_1.getArgument(1) instanceof StringLiteral
			and obj_1.getArgument(2) instanceof Literal
		)
	)
	and target_2.getEnclosingFunction() = func
}

from Function func, Variable vkey_GR_THD_mysql_thread, VariableAccess target_1, BlockStmt target_2
where
not func_0(func)
and func_1(vkey_GR_THD_mysql_thread, target_2, target_1)
and func_2(func, target_2)
and vkey_GR_THD_mysql_thread.getType().hasName("PSI_thread_key")
and not vkey_GR_THD_mysql_thread.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
