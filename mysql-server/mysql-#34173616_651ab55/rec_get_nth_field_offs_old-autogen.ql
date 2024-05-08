/**
 * @name mysql-server-651ab55bd103ff1912e2aeb5c609c0438014d023-rec_get_nth_field_offs_old
 * @id cpp/mysql-server/651ab55bd103ff1912e2aeb5c609c0438014d023/recgetnthfieldoffsold
 * @description mysql-server-651ab55bd103ff1912e2aeb5c609c0438014d023-storage/innobase/rem/rem0wrec.cc-rec_get_nth_field_offs_old mysql-#34173616
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vrec_70, Variable vversion_74, FunctionCall target_3, FunctionCall target_2, FunctionCall target_4, ExprStmt target_5) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		obj_0.getTarget().hasName("rec_old_is_versioned")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vrec_70
	)
	and exists(BlockStmt obj_1 | obj_1=target_1.getThen() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
				obj_3.getLValue().(VariableAccess).getTarget()=vversion_74
				and obj_3.getRValue() instanceof FunctionCall
			)
		)
	)
	and exists(BlockStmt obj_4 | obj_4=target_1.getParent() |
		exists(IfStmt obj_5 | obj_5=obj_4.getParent() |
			obj_5.getThen().(BlockStmt).getStmt(1)=target_1
			and obj_5.getCondition()=target_3
		)
	)
	and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation())
	and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
)
}

predicate func_2(Parameter vrec_70, FunctionCall target_2) {
	target_2.getTarget().hasName("rec_get_instant_row_version_old")
	and target_2.getArgument(0).(VariableAccess).getTarget()=vrec_70
}

predicate func_3(Function func, FunctionCall target_3) {
	target_3.getTarget().hasName("has_row_versions")
	and target_3.getQualifier().(VariableAccess).getTarget().getType().hasName("const dict_index_t *")
	and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vrec_70, FunctionCall target_4) {
	target_4.getTarget().hasName("rec_get_nth_field_offs_old_low")
	and target_4.getArgument(0).(VariableAccess).getTarget()=vrec_70
	and target_4.getArgument(1).(VariableAccess).getTarget().getType().hasName("ulint")
	and target_4.getArgument(2).(VariableAccess).getTarget().getType().hasName("ulint *")
}

predicate func_5(Variable vversion_74, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getRValue() |
			obj_1.getTarget().hasName("get_field_phy_pos")
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("const dict_index_t *")
			and obj_1.getArgument(0).(VariableAccess).getTarget().getType().hasName("ulint")
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vversion_74
		)
		and obj_0.getLValue().(VariableAccess).getTarget().getType().hasName("ulint")
	)
}

from Function func, Parameter vrec_70, Variable vversion_74, FunctionCall target_2, FunctionCall target_3, FunctionCall target_4, ExprStmt target_5
where
not func_1(vrec_70, vversion_74, target_3, target_2, target_4, target_5)
and func_2(vrec_70, target_2)
and func_3(func, target_3)
and func_4(vrec_70, target_4)
and func_5(vversion_74, target_5)
and vrec_70.getType().hasName("const rec_t *")
and vversion_74.getType().hasName("uint8_t")
and vrec_70.getFunction() = func
and vversion_74.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
