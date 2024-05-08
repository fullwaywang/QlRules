/**
 * @name mysql-server-14c90a0c0fe7edb423ca811de5c6212c67cbde14-MoveCompositeIteratorsFromTablePath
 * @id cpp/mysql-server/14c90a0c0fe7edb423ca811de5c6212c67cbde14/movecompositeiteratorsfromtablepath
 * @description mysql-server-14c90a0c0fe7edb423ca811de5c6212c67cbde14-sql/sql_executor.cc-MoveCompositeIteratorsFromTablePath mysql-#35471522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vbottom_of_table_path_1534, Parameter vpath_1531, PointerFieldAccess target_4, ExprStmt target_6) {
exists(ExprStmt target_2 |
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(ReferenceFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().hasName("window")
				and obj_2.getQualifier().(VariableAccess).getTarget()=vbottom_of_table_path_1534
			)
			and obj_1.getTarget().getName()="child"
		)
		and obj_0.getRValue().(VariableAccess).getTarget()=vpath_1531
	)
	and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
	and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
)
}

predicate func_3(PointerFieldAccess target_4, Function func) {
exists(BreakStmt target_3 |
	target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
	and target_3.getEnclosingFunction() = func
)
}

predicate func_4(Variable vbottom_of_table_path_1534, PointerFieldAccess target_4) {
	target_4.getTarget().getName()="type"
	and target_4.getQualifier().(VariableAccess).getTarget()=vbottom_of_table_path_1534
}

predicate func_6(Parameter vpath_1531, ExprStmt target_6) {
	exists(AssignExpr obj_0 | obj_0=target_6.getExpr() |
		exists(ReferenceFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(OverloadedArrayExpr obj_2 | obj_2=obj_1.getQualifier() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					exists(ReferenceFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
						obj_4.getTarget().getName()="param"
						and obj_4.getQualifier().(FunctionCall).getTarget().hasName("materialize")
					)
					and obj_3.getTarget().getName()="query_blocks"
				)
				and obj_2.getAChild().(Literal).getValue()="0"
			)
			and obj_1.getTarget().getName()="subquery_path"
		)
		and obj_0.getRValue().(VariableAccess).getTarget()=vpath_1531
	)
}

from Function func, Variable vbottom_of_table_path_1534, Parameter vpath_1531, PointerFieldAccess target_4, ExprStmt target_6
where
not func_2(vbottom_of_table_path_1534, vpath_1531, target_4, target_6)
and not func_3(target_4, func)
and func_4(vbottom_of_table_path_1534, target_4)
and func_6(vpath_1531, target_6)
and vbottom_of_table_path_1534.getType().hasName("AccessPath *")
and vpath_1531.getType().hasName("AccessPath *")
and vbottom_of_table_path_1534.(LocalVariable).getFunction() = func
and vpath_1531.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
