/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-dict_index_t__get_n_nullable_before__
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/dictindextgetnnullablebefore
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/mtr/mtr0log.cc-dict_index_t__get_n_nullable_before__ mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_3, Function func) {
exists(EmptyStmt target_0 |
	target_0.getLocation().isBefore(target_3.getLocation())
	and target_0.getEnclosingFunction() = func
)
}

predicate func_2(Variable vi_1333, BlockStmt target_4, PointerFieldAccess target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getQualifier() |
		obj_0.getTarget().hasName("get_field")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vi_1333
	)
	and target_2.getTarget().getName()="col"
	and target_2.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vi_1333, IfStmt target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getCondition() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().hasName("get_field")
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_2.getArgument(0).(VariableAccess).getTarget()=vi_1333
			)
			and obj_1.getTarget().getName()="col"
		)
		and obj_0.getTarget().hasName("is_nullable")
	)
	and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_4(Function func, BlockStmt target_4) {
	target_4.getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
	and target_4.getEnclosingFunction() = func
}

from Function func, Variable vi_1333, PointerFieldAccess target_2, IfStmt target_3, BlockStmt target_4
where
not func_0(target_3, func)
and func_2(vi_1333, target_4, target_2)
and func_3(vi_1333, target_3)
and func_4(func, target_4)
and vi_1333.getType().hasName("size_t")
and vi_1333.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
