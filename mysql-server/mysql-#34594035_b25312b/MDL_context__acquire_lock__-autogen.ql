/**
 * @name mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-MDL_context__acquire_lock__
 * @id cpp/mysql-server/b25312b2d666c0589dc688a2d83836d727cb41d0/mdlcontextacquirelock
 * @description mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-sql/sql_audit.cc-MDL_context__acquire_lock__ mysql-#34594035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(0) |
					exists(PointerFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="m_rwlock"
						and obj_4.getQualifier().(VariableAccess).getTarget().getType().hasName("MDL_lock *")
					)
				)
				and obj_2.getTarget().hasName("inline_mysql_prlock_unlock")
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/sql/mdl.cc"
			)
		)
	)
	and target_0.getValue()="3421"
	and not target_0.getValue()="3429"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(0) |
					exists(PointerFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="m_rwlock"
						and obj_4.getQualifier().(VariableAccess).getTarget().getType().hasName("MDL_lock *")
					)
				)
				and obj_2.getTarget().hasName("inline_mysql_prlock_wrlock")
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/sql/mdl.cc"
			)
		)
	)
	and target_1.getValue()="3508"
	and not target_1.getValue()="3516"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(AddressOfExpr obj_3 | obj_3=obj_2.getArgument(0) |
					exists(PointerFieldAccess obj_4 | obj_4=obj_3.getOperand() |
						obj_4.getTarget().getName()="m_rwlock"
						and obj_4.getQualifier().(VariableAccess).getTarget().getType().hasName("MDL_lock *")
					)
				)
				and obj_2.getTarget().hasName("inline_mysql_prlock_unlock")
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/sql/mdl.cc"
			)
		)
	)
	and target_2.getValue()="3510"
	and not target_2.getValue()="3518"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(IfStmt target_4, Function func) {
exists(DoStmt target_3 |
	target_3.getCondition().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
	and target_3.getLocation().isBefore(target_4.getLocation())
)
}

predicate func_4(Function func, IfStmt target_4) {
	exists(EqualityOperation obj_0 | obj_0=target_4.getCondition() |
		obj_0.getLeftOperand().(VariableAccess).getTarget().getType().hasName("Timeout_type")
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(BlockStmt obj_1 | obj_1=target_4.getThen() |
		exists(IfStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getCondition() |
				obj_3.getTarget().hasName("try_acquire_lock")
				and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_3.getArgument(0).(VariableAccess).getTarget().getType().hasName("MDL_request *")
			)
			and obj_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		)
		and exists(IfStmt obj_4 | obj_4=obj_1.getStmt(1) |
			exists(NotExpr obj_5 | obj_5=obj_4.getCondition() |
				exists(PointerFieldAccess obj_6 | obj_6=obj_5.getOperand() |
					obj_6.getTarget().getName()="ticket"
					and obj_6.getQualifier().(VariableAccess).getTarget().getType().hasName("MDL_request *")
				)
			)
			and exists(BlockStmt obj_7 | obj_7=obj_4.getThen() |
				exists(ExprStmt obj_8 | obj_8=obj_7.getStmt(1) |
					exists(FunctionCall obj_9 | obj_9=obj_8.getExpr() |
						obj_9.getTarget().hasName("my_error")
						and obj_9.getArgument(0).(Literal).getValue()="1205"
						and obj_9.getArgument(1).(Literal).getValue()="0"
					)
				)
				and obj_7.getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
			)
		)
	)
	and target_4.getEnclosingFunction() = func
}

from Function func, Literal target_0, Literal target_1, Literal target_2, IfStmt target_4
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and not func_3(target_4, func)
and func_4(func, target_4)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
