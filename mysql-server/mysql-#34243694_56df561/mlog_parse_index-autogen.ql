/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-mlog_parse_index
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/mlogparseindex
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/mtr/mtr0log.cc-mlog_parse_index mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vind_1201) {
exists(FunctionCall target_0 |
	target_0.getTarget().hasName("set_instant_nullable")
	and target_0.getQualifier().(VariableAccess).getTarget()=vind_1201
	and target_0.getArgument(0).(VariableAccess).getType().hasName("size_t")
)
}

predicate func_1(Variable vind_1201, FunctionCall target_1) {
	target_1.getTarget().hasName("get_instant_fields")
	and target_1.getQualifier().(VariableAccess).getTarget()=vind_1201
	and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Variable vind_1201, VariableAccess target_2) {
	target_2.getTarget()=vind_1201
}

predicate func_3(Variable vind_1201, VariableAccess target_3) {
	target_3.getTarget()=vind_1201
}

predicate func_4(Variable vind_1201, AssignExpr target_4) {
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getLValue() |
		obj_0.getTarget().getName()="n_instant_nullable"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vind_1201
	)
	and exists(FunctionCall obj_1 | obj_1=target_4.getRValue() |
		obj_1.getTarget().hasName("get_n_nullable_before")
		and obj_1.getQualifier().(VariableAccess).getTarget()=vind_1201
		and obj_1.getArgument(0) instanceof FunctionCall
	)
}

from Function func, Variable vind_1201, FunctionCall target_1, VariableAccess target_2, VariableAccess target_3, AssignExpr target_4
where
not func_0(vind_1201)
and func_1(vind_1201, target_1)
and func_2(vind_1201, target_2)
and func_3(vind_1201, target_3)
and func_4(vind_1201, target_4)
and vind_1201.getType().hasName("dict_index_t *")
and vind_1201.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
