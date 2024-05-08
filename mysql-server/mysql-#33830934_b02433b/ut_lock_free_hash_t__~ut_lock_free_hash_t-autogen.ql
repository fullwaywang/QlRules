/**
 * @name mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-ut_lock_free_hash_t__~ut_lock_free_hash_t
 * @id cpp/mysql-server/b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23/utlockfreehasht~utlockfreehasht
 * @description mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-storage/innobase/include/ut0lock_free_hash.h-ut_lock_free_hash_t__~ut_lock_free_hash_t mysql-#33830934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable varr_460, FunctionCall target_0) {
	target_0.getTarget().hasName("delete_")
	and not target_0.getTarget().hasName("dealloc")
	and target_0.getArgument(0).(VariableAccess).getTarget()=varr_460
}

predicate func_1(Function func, FunctionCall target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getArgument(0) |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_hollow_objects"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("front")
	)
	and target_1.getTarget().hasName("delete_")
	and not target_1.getTarget().hasName("dealloc")
	and target_1.getEnclosingFunction() = func
}

from Function func, Variable varr_460, FunctionCall target_0, FunctionCall target_1
where
func_0(varr_460, target_0)
and func_1(func, target_1)
and varr_460.getType().hasName("arr_node_t *")
and varr_460.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
