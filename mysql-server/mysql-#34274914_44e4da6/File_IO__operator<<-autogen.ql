/**
 * @name mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-File_IO__operator<<
 * @id cpp/mysql-server/44e4da61d1d1341ecf2b74a99acbc357ca3357cf/fileiooperator<<
 * @description mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-sql/auth/sql_authentication.cc-File_IO__operator<< mysql-#34274914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalOrExpr target_1, Function func) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().getName()="m_file"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("my_sync")
		and obj_0.getArgument(1).(Literal).getValue()="16"
	)
	and target_0.getParent().(IfStmt).getCondition()=target_1
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func, LogicalOrExpr target_1) {
	exists(NotExpr obj_0 | obj_0=target_1.getLeftOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getOperand() |
			obj_1.getTarget().hasName("size")
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("const Sql_string_t &")
		)
	)
	and exists(EqualityOperation obj_2 | obj_2=target_1.getRightOperand() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getRightOperand() |
			exists(PointerFieldAccess obj_4 | obj_4=obj_3.getArgument(0) |
				obj_4.getTarget().getName()="m_file"
				and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and exists(FunctionCall obj_5 | obj_5=obj_3.getArgument(1) |
				obj_5.getTarget().hasName("data")
				and obj_5.getQualifier().(VariableAccess).getTarget().getType().hasName("const Sql_string_t &")
			)
			and exists(FunctionCall obj_6 | obj_6=obj_3.getArgument(2) |
				obj_6.getTarget().hasName("length")
				and obj_6.getQualifier().(VariableAccess).getTarget().getType().hasName("const Sql_string_t &")
			)
			and obj_3.getTarget().hasName("my_write")
			and obj_3.getArgument(3).(BitwiseOrExpr).getValue()="20"
		)
		and obj_2.getLeftOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, LogicalOrExpr target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
