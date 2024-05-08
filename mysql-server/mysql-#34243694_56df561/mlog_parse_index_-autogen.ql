/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-mlog_parse_index_
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/mlogparseindex
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/rem/rec.h-mlog_parse_index_ mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ut_dbg_assertion_failed")
				and obj_2.getArgument(0).(StringLiteral).getValue()="index_log_version <= INDEX_LOG_VERSION"
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/mtr/mtr0log.cc"
			)
		)
	)
	and target_0.getValue()="1162"
	and not target_0.getValue()="1163"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ut_dbg_assertion_failed")
				and obj_2.getArgument(0).(StringLiteral).getValue()="n_uniq + DATA_ROLL_PTR <= n"
				and obj_2.getArgument(1).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/mtr/mtr0log.cc"
			)
		)
	)
	and target_1.getValue()="1207"
	and not target_1.getValue()="1208"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vind_1201) {
exists(FunctionCall target_2 |
	target_2.getTarget().hasName("set_instant_nullable")
	and target_2.getQualifier().(VariableAccess).getTarget()=vind_1201
	and target_2.getArgument(0).(VariableAccess).getType().hasName("size_t")
)
}

predicate func_3(Variable vind_1201, FunctionCall target_3) {
	target_3.getTarget().hasName("get_instant_fields")
	and target_3.getQualifier().(VariableAccess).getTarget()=vind_1201
	and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Variable vind_1201, VariableAccess target_4) {
	target_4.getTarget()=vind_1201
}

predicate func_5(Variable vind_1201, VariableAccess target_5) {
	target_5.getTarget()=vind_1201
}

predicate func_6(Variable vind_1201, AssignExpr target_6) {
	exists(PointerFieldAccess obj_0 | obj_0=target_6.getLValue() |
		obj_0.getTarget().getName()="n_instant_nullable"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vind_1201
	)
	and exists(FunctionCall obj_1 | obj_1=target_6.getRValue() |
		obj_1.getTarget().hasName("get_n_nullable_before")
		and obj_1.getQualifier().(VariableAccess).getTarget()=vind_1201
		and obj_1.getArgument(0) instanceof FunctionCall
	)
}

from Function func, Variable vind_1201, Literal target_0, Literal target_1, FunctionCall target_3, VariableAccess target_4, VariableAccess target_5, AssignExpr target_6
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vind_1201)
and func_3(vind_1201, target_3)
and func_4(vind_1201, target_4)
and func_5(vind_1201, target_5)
and func_6(vind_1201, target_6)
and vind_1201.getType().hasName("dict_index_t *")
and vind_1201.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
