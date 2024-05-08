/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-Gtid__set
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/gtidset
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_gtid.h-Gtid__set mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_1, Function func) {
exists(ExprStmt target_0 |
	target_0.getExpr().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
)
}

predicate func_1(Function func, ExprStmt target_1) {
	exists(AssignExpr obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="sidno"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getRValue().(VariableAccess).getTarget().getType().hasName("rpl_sidno")
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, ExprStmt target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
