/**
 * @name mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-THD__release_resources
 * @id cpp/mysql-server/b25312b2d666c0589dc688a2d83836d727cb41d0/thdreleaseresources
 * @description mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-sql/sql_class.cc-THD__release_resources mysql-#34594035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_1, Function func, ExprStmt target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("mysql_audit_free_thd")
		and obj_0.getArgument(0).(ThisExpr).getType() instanceof PointerType
	)
	and target_1.getLocation().isBefore(target_0.getLocation())
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, IfStmt target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getCondition() |
		obj_0.getTarget().getName()="rli_fake"
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(BlockStmt obj_1 | obj_1=target_1.getThen() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
				exists(PointerFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
					obj_4.getTarget().getName()="rli_fake"
					and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_3.getTarget().hasName("end_info")
			)
		)
		and exists(ExprStmt obj_5 | obj_5=obj_1.getStmt(2) |
			exists(AssignExpr obj_6 | obj_6=obj_5.getExpr() |
				exists(PointerFieldAccess obj_7 | obj_7=obj_6.getLValue() |
					obj_7.getTarget().getName()="rli_fake"
					and obj_7.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and obj_6.getRValue().(Literal).getValue()="0"
			)
		)
		and obj_1.getStmt(1).(ExprStmt).getExpr().(DeleteExpr).getDeallocatorCall().(FunctionCall).getTarget().hasName("operator delete")
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, ExprStmt target_0, IfStmt target_1
where
func_0(target_1, func, target_0)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
