/**
 * @name mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-Mysql_thread__trigger
 * @id cpp/mysql-server/64bbdd9b485884feda5ab193aa1e69a81b2926fe/mysqlthreadtrigger
 * @description mysql-server-64bbdd9b485884feda5ab193aa1e69a81b2926fe-plugin/group_replication/src/thread/mysql_thread.cc-Mysql_thread__trigger mysql-#33025231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vparameters_190, BlockStmt target_3, VariableAccess target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_trigger_queue"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getParent().(IfStmt).getThen()=target_3
	)
	and target_1.getTarget()=vparameters_190
}

predicate func_2(FunctionCall target_4, Function func, ExprStmt target_2) {
	target_2.getExpr().(DeleteExpr).getDeallocatorCall().(FunctionCall).getTarget().hasName("operator delete")
	and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, BlockStmt target_3) {
	exists(ExprStmt obj_0 | obj_0=target_3.getStmt(0) |
		exists(FunctionCall obj_1 | obj_1=obj_0.getExpr() |
			exists(AddressOfExpr obj_2 | obj_2=obj_1.getArgument(0) |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getOperand() |
					obj_3.getTarget().getName()="m_dispatcher_lock"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
			)
			and obj_1.getTarget().hasName("inline_mysql_mutex_unlock")
			and obj_1.getArgument(1) instanceof StringLiteral
			and obj_1.getArgument(2) instanceof Literal
		)
	)
	and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vparameters_190, FunctionCall target_4) {
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getQualifier() |
		obj_0.getTarget().getName()="m_trigger_queue"
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and target_4.getTarget().hasName("push")
	and target_4.getArgument(0).(VariableAccess).getTarget()=vparameters_190
}

from Function func, Parameter vparameters_190, VariableAccess target_1, ExprStmt target_2, BlockStmt target_3, FunctionCall target_4
where
func_1(vparameters_190, target_3, target_1)
and func_2(target_4, func, target_2)
and func_3(func, target_3)
and func_4(vparameters_190, target_4)
and vparameters_190.getType().hasName("Mysql_thread_body_parameters *")
and vparameters_190.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
