/**
 * @name mysql-server-01cd60767c8a98782a3871addec60f32ae1e1337-Persisted_variables_cache__flush_to_file
 * @id cpp/mysql-server/01cd60767c8a98782a3871addec60f32ae1e1337/persistedvariablescacheflushtofile
 * @description mysql-server-01cd60767c8a98782a3871addec60f32ae1e1337-sql/persisted_variable.cc-Persisted_variables_cache__flush_to_file mysql-#33830493
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func, FunctionCall target_0) {
	target_0.getTarget().hasName("open_persist_file")
	and not target_0.getTarget().hasName("open_persist_backup_file")
	and target_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	and target_0.getArgument(0).(BitwiseOrExpr).getValue()="65"
	and target_0.getParent().(IfStmt).getThen()=target_4
	and target_0.getEnclosingFunction() = func
}

predicate func_1(FunctionCall target_0, Function func) {
exists(DoStmt target_1 |
	exists(BlockStmt obj_0 | obj_0=target_1.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getElse().(BlockStmt).getStmt(0)=target_1
			and obj_1.getCondition()=target_0
		)
	)
	and target_1.getCondition().(Literal).getValue()="0"
	and target_1.getEnclosingFunction() = func
)
}

predicate func_2(ExprStmt target_5, Function func) {
exists(DoStmt target_2 |
	target_2.getCondition().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
	and target_2.getLocation().isBefore(target_5.getLocation())
)
}

predicate func_3(Variable vret_795, IfStmt target_6, ExprStmt target_7, LogicalAndExpr target_8, Function func) {
exists(IfStmt target_3 |
	exists(BlockStmt obj_0 | obj_0=target_3.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(1) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getArgument(0) |
					exists(PointerFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
						obj_4.getTarget().getName()="m_persist_backup_filename"
						and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_3.getTarget().hasName("c_str")
				)
				and exists(FunctionCall obj_5 | obj_5=obj_2.getArgument(1) |
					exists(PointerFieldAccess obj_6 | obj_6=obj_5.getQualifier() |
						obj_6.getTarget().getName()="m_persist_filename"
						and obj_6.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_5.getTarget().hasName("c_str")
				)
				and obj_2.getTarget().hasName("my_rename")
				and obj_2.getArgument(2).(Literal).getValue()="16"
			)
		)
		and obj_0.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
	)
	and target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vret_795
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
	and target_3.getLocation().isBefore(target_6.getLocation())
	and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
	and target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation())
)
}

predicate func_4(Variable vret_795, FunctionCall target_0, BlockStmt target_4) {
	exists(ExprStmt obj_0 | obj_0=target_4.getStmt(0) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			obj_1.getLValue().(VariableAccess).getTarget()=vret_795
			and obj_1.getRValue().(Literal).getValue()="1"
		)
	)
	and target_4.getParent().(IfStmt).getCondition()=target_0
}

predicate func_5(Function func, ExprStmt target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getExpr() |
		obj_0.getTarget().hasName("close_persist_file")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vret_795, IfStmt target_6) {
	exists(LogicalAndExpr obj_0 | obj_0=target_6.getCondition() |
		exists(EqualityOperation obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getLeftOperand().(VariableAccess).getTarget()=vret_795
			and obj_1.getRightOperand().(Literal).getValue()="0"
		)
		and exists(EqualityOperation obj_2 | obj_2=obj_0.getRightOperand() |
			obj_2.getLeftOperand().(VariableAccess).getTarget().getType().hasName("bool")
			and obj_2.getRightOperand().(Literal).getValue()="1"
		)
	)
	and exists(ExprStmt obj_3 | obj_3=target_6.getThen() |
		exists(FunctionCall obj_4 | obj_4=obj_3.getExpr() |
			obj_4.getTarget().hasName("clear_sensitive_blob_and_iv")
			and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
	)
}

predicate func_7(Variable vret_795, RelationalOperation target_9, ExprStmt target_7) {
	exists(AssignExpr obj_0 | obj_0=target_7.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vret_795
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_8(Variable vret_795, LogicalAndExpr target_8) {
	exists(EqualityOperation obj_0 | obj_0=target_8.getLeftOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vret_795
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(EqualityOperation obj_1 | obj_1=target_8.getRightOperand() |
		obj_1.getLeftOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and obj_1.getRightOperand().(Literal).getValue()="1"
	)
}

predicate func_9(Function func, RelationalOperation target_9) {
	exists(FunctionCall obj_0 | obj_0=target_9.getLesserOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(2) |
			obj_1.getTarget().hasName("c_ptr")
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("String")
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getArgument(3) |
			obj_2.getTarget().getName()="m_fd"
			and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("inline_mysql_file_fputs")
		and obj_0.getArgument(0) instanceof StringLiteral
		and obj_0.getArgument(1) instanceof Literal
	)
	and  (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
	and target_9.getGreaterOperand().(Literal).getValue()="0"
	and target_9.getEnclosingFunction() = func
}

from Function func, Variable vret_795, FunctionCall target_0, BlockStmt target_4, ExprStmt target_5, IfStmt target_6, ExprStmt target_7, LogicalAndExpr target_8, RelationalOperation target_9
where
func_0(target_4, func, target_0)
and not func_1(target_0, func)
and not func_2(target_5, func)
and not func_3(vret_795, target_6, target_7, target_8, func)
and func_4(vret_795, target_0, target_4)
and func_5(func, target_5)
and func_6(vret_795, target_6)
and func_7(vret_795, target_9, target_7)
and func_8(vret_795, target_8)
and func_9(func, target_9)
and vret_795.getType().hasName("bool")
and vret_795.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
