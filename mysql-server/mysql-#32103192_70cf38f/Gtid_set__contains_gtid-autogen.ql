/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-Gtid_set__contains_gtid
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/gtidsetcontainsgtid
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_gtid_set.cc-Gtid_set__contains_gtid mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_2, Function func, ExprStmt target_0) {
	target_0.getExpr().(Literal).getValue()="0"
	and target_0.getLocation().isBefore(target_2.getLocation())
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
exists(ExprStmt target_1 |
	target_1.getExpr().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getFollowingStmt() instanceof DeclStmt
)
}

predicate func_2(Function func, IfStmt target_2) {
	exists(EqualityOperation obj_0 | obj_0=target_2.getCondition() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getTarget().getName()="sid_lock"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(ExprStmt obj_2 | obj_2=target_2.getThen() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
			exists(PointerFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
				obj_4.getTarget().getName()="sid_lock"
				and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_3.getTarget().hasName("assert_some_lock")
		)
	)
	and target_2.getEnclosingFunction() = func
}

from Function func, ExprStmt target_0, IfStmt target_2
where
func_0(target_2, func, target_0)
and not func_1(func)
and func_2(func, target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
