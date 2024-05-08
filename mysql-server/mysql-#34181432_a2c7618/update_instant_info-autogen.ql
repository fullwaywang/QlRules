/**
 * @name mysql-server-a2c7618a99f4c67c66ab3de77650e7a76122fc54-update_instant_info
 * @id cpp/mysql-server/a2c7618a99f4c67c66ab3de77650e7a76122fc54/updateinstantinfo
 * @description mysql-server-a2c7618a99f4c67c66ab3de77650e7a76122fc54-storage/innobase/mtr/mtr0log.cc-update_instant_info mysql-#34181432
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfield_1071, ValueFieldAccess target_0) {
	target_0.getTarget().getName()="phy_pos"
	and target_0.getQualifier().(VariableAccess).getTarget()=vfield_1071
}

predicate func_1(Variable vn_dropped_1069, Variable vfield_1071, Variable vcol_1072, Variable vis_dropped_1074, IfStmt target_2, IfStmt target_1) {
	exists(BlockStmt obj_0 | obj_0=target_1.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="v_dropped"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vfield_1071
				)
				and obj_2.getTarget().hasName("set_version_dropped")
				and obj_2.getQualifier().(VariableAccess).getTarget()=vcol_1072
			)
		)
		and obj_0.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vn_dropped_1069
	)
	and target_1.getCondition().(VariableAccess).getTarget()=vis_dropped_1074
	and target_2.getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vfield_1071, Variable vcol_1072, IfStmt target_2) {
	exists(BlockStmt obj_0 | obj_0=target_2.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="v_added"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vfield_1071
				)
				and obj_2.getTarget().hasName("set_version_added")
				and obj_2.getQualifier().(VariableAccess).getTarget()=vcol_1072
			)
		)
		and obj_0.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("size_t")
	)
	and target_2.getCondition().(VariableAccess).getTarget().getType().hasName("bool")
}

from Function func, Variable vn_dropped_1069, Variable vfield_1071, Variable vcol_1072, Variable vis_dropped_1074, ValueFieldAccess target_0, IfStmt target_1, IfStmt target_2
where
func_0(vfield_1071, target_0)
and func_1(vn_dropped_1069, vfield_1071, vcol_1072, vis_dropped_1074, target_2, target_1)
and func_2(vfield_1071, vcol_1072, target_2)
and vn_dropped_1069.getType().hasName("size_t")
and vfield_1071.getType().hasName("Field_instant_info")
and vcol_1072.getType().hasName("dict_col_t *")
and vis_dropped_1074.getType().hasName("bool")
and vn_dropped_1069.(LocalVariable).getFunction() = func
and vfield_1071.(LocalVariable).getFunction() = func
and vcol_1072.(LocalVariable).getFunction() = func
and vis_dropped_1074.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
