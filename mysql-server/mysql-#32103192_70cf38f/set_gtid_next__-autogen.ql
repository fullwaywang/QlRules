/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-set_gtid_next__
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/setgtidnext
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_gtid_owned.cc-set_gtid_next__ mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(NotExpr target_3, Function func) {
exists(ExprStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getThen().(BlockStmt).getStmt(3)=target_0
			and obj_1.getCondition()=target_3
		)
	)
	and target_0.getExpr().(Literal).getValue()="0"
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(NotExpr target_3, Function func) {
exists(ExprStmt target_1 |
	exists(BlockStmt obj_0 | obj_0=target_1.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getThen().(BlockStmt).getStmt(4)=target_1
			and obj_1.getCondition()=target_3
		)
	)
	and target_1.getExpr().(Literal).getValue()="0"
	and target_1.getEnclosingFunction() = func
)
}

predicate func_2(NotExpr target_3, Function func, ExprStmt target_2) {
	target_2.getExpr().(Literal).getValue()="0"
	and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, NotExpr target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getOperand() |
		exists(ReferenceFieldAccess obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().getName()="gtid"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("const Gtid_specification &")
		)
		and obj_0.getTarget().hasName("is_owned")
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("Gtid_state *")
	)
	and target_3.getEnclosingFunction() = func
}

from Function func, ExprStmt target_2, NotExpr target_3
where
not func_0(target_3, func)
and not func_1(target_3, func)
and func_2(target_3, func, target_2)
and func_3(func, target_3)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
