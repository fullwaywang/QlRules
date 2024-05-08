/**
 * @name mysql-server-a09849ebc036a0155d9137981137f574c8621716-locksys__rec_lock_has_to_wait
 * @id cpp/mysql-server/a09849ebc036a0155d9137981137f574c8621716/locksysreclockhastowait
 * @description mysql-server-a09849ebc036a0155d9137981137f574c8621716-storage/innobase/lock/lock0lock.cc-locksys__rec_lock_has_to_wait mysql-#34123159
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlock1_575, Parameter vlock2_576, Parameter vlock1_cache_577, FunctionCall target_3) {
exists(EqualityOperation target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getLeftOperand() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().getName()="trx"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vlock1_575
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getArgument(1) |
			obj_2.getTarget().getName()="type_mode"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vlock1_575
		)
		and obj_0.getTarget().hasName("rec_lock_check_conflict")
		and obj_0.getArgument(2).(VariableAccess).getTarget()=vlock2_576
		and obj_0.getArgument(3) instanceof FunctionCall
		and obj_0.getArgument(4).(VariableAccess).getTarget()=vlock1_cache_577
		and obj_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
	)
)
}

predicate func_1(Parameter vlock1_575, PointerFieldAccess target_1) {
	target_1.getTarget().getName()="trx"
	and target_1.getQualifier().(VariableAccess).getTarget()=vlock1_575
	and target_1.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vlock1_575, PointerFieldAccess target_2) {
	target_2.getTarget().getName()="type_mode"
	and target_2.getQualifier().(VariableAccess).getTarget()=vlock1_575
	and target_2.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vlock1_575, FunctionCall target_3) {
	target_3.getTarget().hasName("includes_supremum")
	and target_3.getQualifier().(VariableAccess).getTarget()=vlock1_575
	and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vlock2_576, VariableAccess target_4) {
	target_4.getTarget()=vlock2_576
	and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Parameter vlock1_cache_577, VariableAccess target_5) {
	target_5.getTarget()=vlock1_cache_577
	and target_5.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vlock1_575, Parameter vlock2_576, Parameter vlock1_cache_577, FunctionCall target_6) {
	exists(PointerFieldAccess obj_0 | obj_0=target_6.getArgument(0) |
		obj_0.getTarget().getName()="trx"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vlock1_575
	)
	and exists(PointerFieldAccess obj_1 | obj_1=target_6.getArgument(1) |
		obj_1.getTarget().getName()="type_mode"
		and obj_1.getQualifier().(VariableAccess).getTarget()=vlock1_575
	)
	and target_6.getTarget().hasName("rec_lock_has_to_wait")
	and target_6.getArgument(2).(VariableAccess).getTarget()=vlock2_576
	and target_6.getArgument(3) instanceof FunctionCall
	and target_6.getArgument(4).(VariableAccess).getTarget()=vlock1_cache_577
}

from Function func, Parameter vlock1_575, Parameter vlock2_576, Parameter vlock1_cache_577, PointerFieldAccess target_1, PointerFieldAccess target_2, FunctionCall target_3, VariableAccess target_4, VariableAccess target_5, FunctionCall target_6
where
not func_0(vlock1_575, vlock2_576, vlock1_cache_577, target_3)
and func_1(vlock1_575, target_1)
and func_2(vlock1_575, target_2)
and func_3(vlock1_575, target_3)
and func_4(vlock2_576, target_4)
and func_5(vlock1_cache_577, target_5)
and func_6(vlock1_575, vlock2_576, vlock1_cache_577, target_6)
and vlock1_575.getType().hasName("const ib_lock_t *")
and vlock2_576.getType().hasName("const ib_lock_t *")
and vlock1_cache_577.getType().hasName("Trx_locks_cache &")
and vlock1_575.getFunction() = func
and vlock2_576.getFunction() = func
and vlock1_cache_577.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
