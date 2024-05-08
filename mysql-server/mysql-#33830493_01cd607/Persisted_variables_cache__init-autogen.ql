/**
 * @name mysql-server-01cd60767c8a98782a3871addec60f32ae1e1337-Persisted_variables_cache__init
 * @id cpp/mysql-server/01cd60767c8a98782a3871addec60f32ae1e1337/persistedvariablescacheinit
 * @description mysql-server-01cd60767c8a98782a3871addec60f32ae1e1337-sql/persisted_variable.cc-Persisted_variables_cache__init mysql-#33830493
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_1, Function func) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_persist_backup_filename"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and exists(FunctionCall obj_2 | obj_2=obj_0.getArgument(0) |
			exists(PointerFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
				obj_3.getTarget().getName()="m_persist_filename"
				and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_2.getTarget().hasName("operator+")
			and obj_2.getArgument(1).(StringLiteral).getValue()=".backup"
		)
		and obj_0.getTarget().hasName("operator=")
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
)
}

predicate func_1(Function func, ExprStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		exists(AddressOfExpr obj_1 | obj_1=obj_0.getArgument(1) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getOperand() |
				obj_2.getTarget().getName()="m_LOCK_persist_variables"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
		)
		and obj_0.getTarget().hasName("inline_mysql_mutex_init")
		and obj_0.getArgument(0).(VariableAccess).getTarget().getType().hasName("PSI_mutex_key")
		and obj_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("native_mutexattr_t")
		and obj_0.getArgument(3) instanceof StringLiteral
		and obj_0.getArgument(4) instanceof Literal
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, ExprStmt target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
