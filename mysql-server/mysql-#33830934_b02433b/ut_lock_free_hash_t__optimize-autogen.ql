/**
 * @name mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-ut_lock_free_hash_t__optimize
 * @id cpp/mysql-server/b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23/utlockfreehashtoptimize
 * @description mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-storage/innobase/include/ut0lock_free_hash.h-ut_lock_free_hash_t__optimize mysql-#33830934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
	target_0.getValue()="m_data.compare_exchange_strong(expected, next, std::memory_order_relaxed)"
	and not target_0.getValue()="m_data.compare_exchange_strong(expected, next)"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable varr_983, FunctionCall target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getArgument(0) |
		obj_0.getTarget().getName()="m_base"
		and obj_0.getQualifier().(VariableAccess).getTarget()=varr_983
	)
	and target_1.getTarget().hasName("delete_arr")
	and not target_1.getTarget().hasName("await_release_of_old_references")
}

predicate func_2(ExprStmt target_14, Function func, ExprStmt target_2) {
	target_2.getExpr() instanceof AssignExpr
	and target_14.getLocation().isBefore(target_2.getLocation())
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable varr_983, ExprStmt target_15) {
exists(FunctionCall target_3 |
	exists(PointerFieldAccess obj_0 | obj_0=target_3.getQualifier() |
		exists(VariableAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget()=varr_983
			and obj_1.getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		)
		and obj_0.getTarget().getName()="m_base"
	)
	and target_3.getTarget().hasName("reset")
)
}

predicate func_4(Variable varr_983, PointerFieldAccess target_4) {
	exists(AssignExpr obj_0 | obj_0=target_4.getParent() |
		obj_0.getLValue() = target_4
		and obj_0.getRValue() instanceof Literal
	)
	and target_4.getTarget().getName()="m_base"
	and target_4.getQualifier().(VariableAccess).getTarget()=varr_983
}

predicate func_5(Variable varr_983, VariableAccess target_5) {
	target_5.getTarget()=varr_983
}

predicate func_10(Variable varr_983, WhileStmt target_10) {
	exists(RelationalOperation obj_0 | obj_0=target_10.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getGreaterOperand() |
			obj_1.getTarget().hasName("n_ref")
			and obj_1.getQualifier().(VariableAccess).getTarget()=varr_983
		)
		and obj_0.getLesserOperand().(Literal).getValue()="0"
	)
}

predicate func_12(Variable varr_983, ExprStmt target_2, VariableAccess target_12) {
	target_12.getTarget()=varr_983
	and target_12.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Variable varr_983, AssignExpr target_13) {
	exists(PointerFieldAccess obj_0 | obj_0=target_13.getLValue() |
		obj_0.getTarget().getName()="m_base"
		and obj_0.getQualifier().(VariableAccess).getTarget()=varr_983
	)
	and target_13.getRValue().(Literal).getValue()="0"
}

predicate func_14(Function func, ExprStmt target_14) {
	target_14.getExpr() instanceof FunctionCall
	and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable varr_983, ExprStmt target_15) {
	exists(FunctionCall obj_0 | obj_0=target_15.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_hollow_objects"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("push_back")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=varr_983
	)
}

from Function func, Variable varr_983, StringLiteral target_0, FunctionCall target_1, ExprStmt target_2, PointerFieldAccess target_4, VariableAccess target_5, WhileStmt target_10, VariableAccess target_12, AssignExpr target_13, ExprStmt target_14, ExprStmt target_15
where
func_0(func, target_0)
and func_1(varr_983, target_1)
and func_2(target_14, func, target_2)
and not func_3(varr_983, target_15)
and func_4(varr_983, target_4)
and func_5(varr_983, target_5)
and func_10(varr_983, target_10)
and func_12(varr_983, target_2, target_12)
and func_13(varr_983, target_13)
and func_14(func, target_14)
and func_15(varr_983, target_15)
and varr_983.getType().hasName("arr_node_t *")
and varr_983.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
