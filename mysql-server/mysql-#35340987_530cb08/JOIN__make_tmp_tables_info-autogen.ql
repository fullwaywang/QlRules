/**
 * @name mysql-server-530cb08eacf9c141c101798412fb9ffe16ef06c3-JOIN__make_tmp_tables_info
 * @id cpp/mysql-server/530cb08eacf9c141c101798412fb9ffe16ef06c3/joinmaketmptablesinfo
 * @description mysql-server-530cb08eacf9c141c101798412fb9ffe16ef06c3-sql/sql_select.cc-JOIN__make_tmp_tables_info mysql-#35340987
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_1, Function func) {
exists(IfStmt target_0 |
	exists(RelationalOperation obj_0 | obj_0=target_0.getCondition() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getGreaterOperand() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="m_windows"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_1.getTarget().getName()="elements"
		)
		and obj_0.getLesserOperand().(Literal).getValue()="0"
	)
	and exists(RangeBasedForStmt obj_3 | obj_3=target_0.getThen() |
		exists(FunctionCall obj_4 | obj_4=obj_3.getCondition() |
			obj_4.getTarget().hasName("operator!=")
			and obj_4.getQualifier().(VariableAccess).getType().hasName("iterator")
			and obj_4.getArgument(0).(VariableAccess).getType().hasName("iterator")
		)
		and exists(FunctionCall obj_5 | obj_5=obj_3.getUpdate() |
			obj_5.getTarget().hasName("operator++")
			and obj_5.getQualifier().(VariableAccess).getType().hasName("iterator")
		)
		and exists(ExprStmt obj_6 | obj_6=obj_3.getStmt() |
			exists(FunctionCall obj_7 | obj_7=obj_6.getExpr() |
				obj_7.getTarget().hasName("update_used_tables")
				and obj_7.getQualifier().(VariableAccess).getType().hasName("Item *")
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
)
}

predicate func_1(Function func, ExprStmt target_1) {
	exists(AssignExpr obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="having_for_explain"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().getName()="having_cond"
			and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, ExprStmt target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
