/**
 * @name mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-MDL_context__acquire_lock
 * @id cpp/mysql-server/b25312b2d666c0589dc688a2d83836d727cb41d0/mdlcontextacquirelock
 * @description mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-sql/mdl.cc-MDL_context__acquire_lock mysql-#34594035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(AssignExpr obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getArgument(1) |
					obj_3.getTarget().getName()="m_psi"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("MDL_ticket *")
				)
				and obj_2.getTarget().hasName("pfs_start_metadata_wait_vc")
				and obj_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("PSI_metadata_locker_state")
				and obj_2.getArgument(2).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/sql/mdl.cc"
			)
		)
	)
	and target_0.getValue()="3429"
	and not target_0.getValue()="3437"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(IfStmt target_2, Function func) {
exists(DoStmt target_1 |
	target_1.getCondition().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_2.getLocation())
)
}

predicate func_2(Function func, IfStmt target_2) {
	exists(EqualityOperation obj_0 | obj_0=target_2.getCondition() |
		obj_0.getLeftOperand().(VariableAccess).getTarget().getType().hasName("Timeout_type")
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(BlockStmt obj_1 | obj_1=target_2.getThen() |
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
	and target_2.getEnclosingFunction() = func
}

from Function func, Literal target_0, IfStmt target_2
where
func_0(func, target_0)
and not func_1(target_2, func)
and func_2(func, target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
