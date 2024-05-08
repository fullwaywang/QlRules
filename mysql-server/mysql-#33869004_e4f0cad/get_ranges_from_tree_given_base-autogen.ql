/**
 * @name mysql-server-e4f0cad8ef2b2f0e84a23f8ebeed5990796efd26-get_ranges_from_tree_given_base
 * @id cpp/mysql-server/e4f0cad8ef2b2f0e84a23f8ebeed5990796efd26/getrangesfromtreegivenbase
 * @description mysql-server-e4f0cad8ef2b2f0e84a23f8ebeed5990796efd26-sql/range_optimizer/index_range_scan_plan.cc-get_ranges_from_tree_given_base mysql-#33869004
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(BlockStmt target_4, Function func) {
exists(LogicalOrExpr target_2 |
	exists(FunctionCall obj_0 | obj_0=target_2.getRightOperand() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="killed"
			and obj_1.getQualifier().(VariableAccess).getType().hasName("THD *")
		)
		and obj_0.getTarget().hasName("operator THD::killed_state")
	)
	and target_2.getLeftOperand() instanceof EqualityOperation
	and target_2.getParent().(IfStmt).getThen()=target_4
	and target_2.getEnclosingFunction() = func
)
}

predicate func_3(Variable vrange_1185, BlockStmt target_4, EqualityOperation target_3) {
	target_3.getLeftOperand().(VariableAccess).getTarget()=vrange_1185
	and target_3.getRightOperand().(Literal).getValue()="0"
	and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(EqualityOperation target_3, Function func, BlockStmt target_4) {
	target_4.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
	and target_4.getParent().(IfStmt).getCondition()=target_3
	and target_4.getEnclosingFunction() = func
}

from Function func, Variable vrange_1185, EqualityOperation target_3, BlockStmt target_4
where
not func_2(target_4, func)
and func_3(vrange_1185, target_4, target_3)
and func_4(target_3, func, target_4)
and vrange_1185.getType().hasName("QUICK_RANGE *")
and vrange_1185.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
