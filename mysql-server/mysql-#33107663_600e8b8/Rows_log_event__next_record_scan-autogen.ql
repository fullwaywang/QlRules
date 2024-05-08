/**
 * @name mysql-server-600e8b8f0912111659ce6a6d4be74f5225057211-Rows_log_event__next_record_scan
 * @id cpp/mysql-server/600e8b8f0912111659ce6a6d4be74f5225057211/rowslogeventnextrecordscan
 * @description mysql-server-600e8b8f0912111659ce6a6d4be74f5225057211-sql/log_event.cc-Rows_log_event__next_record_scan mysql-#33107663
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verror_8763, FunctionCall target_4, IfStmt target_5) {
exists(IfStmt target_0 |
	exists(NotExpr obj_0 | obj_0=target_0.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getOperand() |
			obj_1.getTarget().hasName("is_trx_retryable_upon_engine_error")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=verror_8763
		)
	)
	and exists(BlockStmt obj_2 | obj_2=target_0.getParent() |
		exists(IfStmt obj_3 | obj_3=obj_2.getParent() |
			obj_3.getElse().(BlockStmt).getStmt(0)=target_0
			and obj_3.getCondition()=target_4
		)
	)
	and target_0.getThen() instanceof ExprStmt
	and target_5.getCondition().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_1(Variable verror_8763, AssignExpr target_6) {
exists(IfStmt target_1 |
	exists(NotExpr obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getOperand() |
			obj_1.getTarget().hasName("is_trx_retryable_upon_engine_error")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=verror_8763
		)
	)
	and exists(BlockStmt obj_2 | obj_2=target_1.getParent() |
		exists(IfStmt obj_3 | obj_3=obj_2.getParent() |
			obj_3.getThen().(BlockStmt).getStmt(1)=target_1
			and obj_3.getCondition()=target_6
		)
	)
	and target_1.getThen() instanceof ExprStmt
)
}

predicate func_2(Variable verror_8763, FunctionCall target_4, ExprStmt target_2) {
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=verror_8763
		and obj_0.getRValue().(Literal).getValue()="120"
	)
	and target_2.getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable verror_8763, AssignExpr target_6, ExprStmt target_3) {
	exists(AssignExpr obj_0 | obj_0=target_3.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=verror_8763
		and obj_0.getRValue().(Literal).getValue()="120"
	)
	and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_4(Function func, FunctionCall target_4) {
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getQualifier() |
		obj_0.getTarget().getName()="m_itr"
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(FunctionCall obj_1 | obj_1=target_4.getArgument(0) |
		exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
			obj_2.getTarget().getName()="m_distinct_keys"
			and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_1.getTarget().hasName("end")
	)
	and target_4.getTarget().hasName("operator!=")
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable verror_8763, IfStmt target_5) {
	exists(BlockStmt obj_0 | obj_0=target_5.getThen() |
		exists(IfStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getCondition() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="m_itr"
					and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
				)
				and exists(FunctionCall obj_4 | obj_4=obj_2.getArgument(0) |
					exists(PointerFieldAccess obj_5 | obj_5=obj_4.getQualifier() |
						obj_5.getTarget().getName()="m_distinct_keys"
						and obj_5.getQualifier().(ThisExpr).getType() instanceof PointerType
					)
					and obj_4.getTarget().hasName("end")
				)
				and obj_2.getTarget().hasName("operator!=")
			)
			and exists(BlockStmt obj_6 | obj_6=obj_1.getThen() |
				exists(ExprStmt obj_7 | obj_7=obj_6.getStmt(1) |
					exists(FunctionCall obj_8 | obj_8=obj_7.getExpr() |
						obj_8.getTarget().hasName("operator++")
						and obj_8.getQualifier().(PointerFieldAccess).getTarget().getName()="m_itr"
						and obj_8.getArgument(0).(Literal).getValue()="0"
					)
				)
				and exists(ExprStmt obj_9 | obj_9=obj_6.getStmt(2) |
					exists(AssignExpr obj_10 | obj_10=obj_9.getExpr() |
						obj_10.getLValue().(VariableAccess).getTarget().getType().hasName("bool")
						and obj_10.getRValue().(Literal).getValue()="1"
					)
				)
				and obj_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_key"
			)
			and obj_1.getElse() instanceof ExprStmt
		)
	)
	and target_5.getCondition().(VariableAccess).getTarget()=verror_8763
}

predicate func_6(Variable verror_8763, AssignExpr target_6) {
	exists(FunctionCall obj_0 | obj_0=target_6.getRValue() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="file"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("TABLE *")
		)
		and exists(ArrayExpr obj_2 | obj_2=obj_0.getArgument(0) |
			exists(PointerFieldAccess obj_3 | obj_3=obj_2.getArrayBase() |
				obj_3.getTarget().getName()="record"
				and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("TABLE *")
			)
			and obj_2.getArrayOffset().(Literal).getValue()="0"
		)
		and exists(PointerFieldAccess obj_4 | obj_4=obj_0.getArgument(1) |
			obj_4.getTarget().getName()="m_key"
			and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("ha_index_read_map")
		and obj_0.getArgument(2).(ComplementExpr).getValue()="18446744073709551615"
	)
	and target_6.getLValue().(VariableAccess).getTarget()=verror_8763
}

from Function func, Variable verror_8763, ExprStmt target_2, ExprStmt target_3, FunctionCall target_4, IfStmt target_5, AssignExpr target_6
where
not func_0(verror_8763, target_4, target_5)
and not func_1(verror_8763, target_6)
and func_2(verror_8763, target_4, target_2)
and func_3(verror_8763, target_6, target_3)
and func_4(func, target_4)
and func_5(verror_8763, target_5)
and func_6(verror_8763, target_6)
and verror_8763.getType().hasName("int")
and verror_8763.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
