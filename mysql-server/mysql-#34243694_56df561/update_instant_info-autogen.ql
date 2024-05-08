/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-update_instant_info
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/updateinstantinfo
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/mtr/mtr0log.cc-update_instant_info mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vindex_1083, Variable vn_dropped_1089, ExprStmt target_1, Function func) {
exists(ExprStmt target_0 |
	exists(AssignSubExpr obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="table"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vindex_1083
			)
			and obj_1.getTarget().getName()="n_cols"
		)
		and obj_0.getRValue().(VariableAccess).getTarget()=vn_dropped_1089
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getFollowingStmt() instanceof ReturnStmt
	and target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vindex_1083, Variable vn_dropped_1089, ExprStmt target_1) {
	exists(AssignSubExpr obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="table"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vindex_1083
			)
			and obj_1.getTarget().getName()="current_col_count"
		)
		and obj_0.getRValue().(VariableAccess).getTarget()=vn_dropped_1089
	)
}

from Function func, Parameter vindex_1083, Variable vn_dropped_1089, ExprStmt target_1
where
not func_0(vindex_1083, vn_dropped_1089, target_1, func)
and func_1(vindex_1083, vn_dropped_1089, target_1)
and vindex_1083.getType().hasName("dict_index_t *")
and vn_dropped_1089.getType().hasName("size_t")
and vindex_1083.getFunction() = func
and vn_dropped_1089.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
