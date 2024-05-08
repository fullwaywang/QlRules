/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-dict_index_add_to_cache_w_vcol_
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/dictindexaddtocachewvcol
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/include/dict0mem.h-dict_index_add_to_cache_w_vcol_ mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vnew_index_2427, FunctionCall target_1) {
	target_1.getTarget().hasName("get_instant_fields")
	and target_1.getQualifier().(VariableAccess).getTarget()=vnew_index_2427
	and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0) instanceof FunctionCall
}

/*predicate func_2(Variable vnew_index_2427, VariableAccess target_2) {
	target_2.getTarget()=vnew_index_2427
}

*/
predicate func_3(Variable vnew_index_2427, VariableAccess target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(ExprStmt obj_2 | obj_2=obj_1.getParent() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
					obj_3.getTarget().hasName("set_instant_nullable")
					and obj_3.getQualifier().(VariableAccess).getTarget()=vnew_index_2427
					and obj_3.getArgument(0) instanceof FunctionCall
				)
			)
		)
	)
	and target_3.getTarget()=vnew_index_2427
}

predicate func_4(Variable vnew_index_2427, FunctionCall target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("set_instant_nullable")
				and obj_2.getQualifier().(VariableAccess).getTarget()=vnew_index_2427
			)
		)
	)
	and target_4.getTarget().hasName("get_n_nullable_before")
	and target_4.getQualifier().(VariableAccess).getTarget()=vnew_index_2427
	and target_4.getArgument(0) instanceof FunctionCall
}

from Function func, Variable vnew_index_2427, FunctionCall target_1, VariableAccess target_3, FunctionCall target_4
where
func_1(vnew_index_2427, target_1)
and func_3(vnew_index_2427, target_3)
and func_4(vnew_index_2427, target_4)
and vnew_index_2427.getType().hasName("dict_index_t *")
and vnew_index_2427.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
