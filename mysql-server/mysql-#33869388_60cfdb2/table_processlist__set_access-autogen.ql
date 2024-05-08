/**
 * @name mysql-server-60cfdb2127c821ab92269b3fa3f9d7dabebbb637-table_processlist__set_access
 * @id cpp/mysql-server/60cfdb2127c821ab92269b3fa3f9d7dabebbb637/tableprocesslistsetaccess
 * @description mysql-server-60cfdb2127c821ab92269b3fa3f9d7dabebbb637-storage/perfschema/table_processlist.cc-table_processlist__set_access mysql-#33869388
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vthd_99, IfStmt target_1, IfStmt target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().hasName("security_context")
			and obj_1.getQualifier().(VariableAccess).getTarget()=vthd_99
		)
		and obj_0.getTarget().hasName("check_access")
		and obj_0.getArgument(0).(BinaryBitwiseOperation).getValue()="256"
	)
	and exists(BlockStmt obj_2 | obj_2=target_0.getThen() |
		exists(ExprStmt obj_3 | obj_3=obj_2.getStmt(0) |
			exists(AssignExpr obj_4 | obj_4=obj_3.getExpr() |
				exists(ValueFieldAccess obj_5 | obj_5=obj_4.getLValue() |
					exists(PointerFieldAccess obj_6 | obj_6=obj_5.getQualifier() |
						obj_6.getTarget().getName()="m_row_priv"
						and obj_6.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_5.getTarget().getName()="m_auth"
				)
			)
		)
		and obj_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
	)
	and target_1.getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Function func, IfStmt target_1) {
	exists(EqualityOperation obj_0 | obj_0=target_1.getCondition() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getTarget().getName()="length"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("LEX_CSTRING")
		)
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(BlockStmt obj_2 | obj_2=target_1.getThen() |
		exists(ExprStmt obj_3 | obj_3=obj_2.getStmt(0) |
			exists(AssignExpr obj_4 | obj_4=obj_3.getExpr() |
				exists(ValueFieldAccess obj_5 | obj_5=obj_4.getLValue() |
					exists(PointerFieldAccess obj_6 | obj_6=obj_5.getQualifier() |
						obj_6.getTarget().getName()="m_row_priv"
						and obj_6.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_5.getTarget().getName()="m_auth"
				)
			)
		)
		and obj_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, Variable vthd_99, IfStmt target_0, IfStmt target_1
where
func_0(vthd_99, target_1, target_0)
and func_1(func, target_1)
and vthd_99.getType().hasName("THD *")
and vthd_99.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
