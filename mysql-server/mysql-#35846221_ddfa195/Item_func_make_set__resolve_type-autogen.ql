/**
 * @name mysql-server-ddfa195e8dfc6ac355dfb43d9e8349315409509f-Item_func_make_set__resolve_type
 * @id cpp/mysql-server/ddfa195e8dfc6ac355dfb43d9e8349315409509f/itemfuncmakesetresolvetype
 * @description mysql-server-ddfa195e8dfc6ac355dfb43d9e8349315409509f-sql/item_strfunc.cc-Item_func_make_set__resolve_type mysql-#35846221
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, ExprStmt target_0) {
	exists(AssignOrExpr obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="used_tables_cache"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and exists(FunctionCall obj_2 | obj_2=obj_0.getRValue() |
			exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
				obj_3.getTarget().getName()="item"
				and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_2.getTarget().hasName("used_tables")
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Function func, ExprStmt target_1) {
	exists(AssignAndExpr obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="not_null_tables_cache"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and exists(FunctionCall obj_2 | obj_2=obj_0.getRValue() |
			exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
				obj_3.getTarget().getName()="item"
				and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_2.getTarget().hasName("not_null_tables")
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Function func, ExprStmt target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().getName()="item"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("add_accum_properties")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
