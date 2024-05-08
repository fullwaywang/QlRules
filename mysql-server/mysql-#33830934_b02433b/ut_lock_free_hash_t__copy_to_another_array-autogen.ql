/**
 * @name mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-ut_lock_free_hash_t__copy_to_another_array
 * @id cpp/mysql-server/b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23/utlockfreehashtcopytoanotherarray
 * @description mysql-server-b02433bb10f2a93cd9fbb0b43e39b1a4ba46ea23-storage/innobase/include/ut0lock_free_hash.h-ut_lock_free_hash_t__copy_to_another_array mysql-#33830934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_868, Parameter vsrc_arr_867) {
exists(OverloadedArrayExpr target_0 |
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_base"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vsrc_arr_867
	)
	and target_0.getAChild().(VariableAccess).getTarget()=vi_868
)
}

/*predicate func_1(Parameter vsrc_arr_867, VariableAccess target_1) {
	target_1.getTarget()=vsrc_arr_867
}

*/
predicate func_2(Variable vi_868, Parameter vsrc_arr_867, VariableAccess target_2) {
	exists(ArrayExpr obj_0 | obj_0=target_2.getParent() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArrayBase() |
			obj_1.getTarget().getName()="m_base"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vsrc_arr_867
		)
	)
	and target_2.getTarget()=vi_868
}

predicate func_3(Variable vi_868, Parameter vsrc_arr_867, ArrayExpr target_3) {
	exists(PointerFieldAccess obj_0 | obj_0=target_3.getArrayBase() |
		obj_0.getTarget().getName()="m_base"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vsrc_arr_867
	)
	and target_3.getArrayOffset().(VariableAccess).getTarget()=vi_868
}

predicate func_5(Function func, ExprStmt target_5) {
	target_5.getExpr().(FunctionCall).getTarget().hasName("atomic_thread_fence")
	and target_5.getEnclosingFunction() = func
}

from Function func, Variable vi_868, Parameter vsrc_arr_867, VariableAccess target_2, ArrayExpr target_3, ExprStmt target_5
where
not func_0(vi_868, vsrc_arr_867)
and func_2(vi_868, vsrc_arr_867, target_2)
and func_3(vi_868, vsrc_arr_867, target_3)
and func_5(func, target_5)
and vi_868.getType().hasName("size_t")
and vsrc_arr_867.getType().hasName("arr_node_t *")
and vi_868.(LocalVariable).getFunction() = func
and vsrc_arr_867.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
