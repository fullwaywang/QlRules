/**
 * @name mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-rec_init_null_and_len_comp
 * @id cpp/mysql-server/56df561e994d5d9f6a95ee3faed976ebf522f85a/recinitnullandlencomp
 * @description mysql-server-56df561e994d5d9f6a95ee3faed976ebf522f85a-storage/innobase/rem/rec.h-rec_init_null_and_len_comp mysql-#34243694
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vindex_793, Variable vnon_default_fields_797, FunctionCall target_4, ExprStmt target_5) {
exists(FunctionCall target_0 |
	exists(AssignExpr obj_0 | obj_0=target_0.getParent() |
		obj_0.getRValue() = target_0
		and obj_0.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint16_t *")
	)
	and target_0.getTarget().hasName("calculate_n_instant_nullable")
	and target_0.getQualifier().(VariableAccess).getTarget()=vindex_793
	and target_0.getArgument(0).(VariableAccess).getTarget()=vnon_default_fields_797
	and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vindex_793, VariableAccess target_1) {
	target_1.getTarget()=vindex_793
}

predicate func_2(Variable vnon_default_fields_797, VariableAccess target_2) {
	target_2.getTarget()=vnon_default_fields_797
	and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vindex_793, Variable vnon_default_fields_797, FunctionCall target_3) {
	exists(AssignExpr obj_0 | obj_0=target_3.getParent() |
		obj_0.getRValue() = target_3
		and obj_0.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint16_t *")
	)
	and target_3.getTarget().hasName("get_n_nullable_before")
	and target_3.getQualifier().(VariableAccess).getTarget()=vindex_793
	and target_3.getArgument(0).(VariableAccess).getTarget()=vnon_default_fields_797
}

predicate func_4(Parameter vindex_793, FunctionCall target_4) {
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getQualifier() |
		obj_0.getTarget().getName()="table"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vindex_793
	)
	and target_4.getTarget().hasName("has_instant_cols")
}

predicate func_5(Variable vnon_default_fields_797, FunctionCall target_6, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and obj_0.getRValue().(VariableAccess).getTarget()=vnon_default_fields_797
	)
	and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_6(Function func, FunctionCall target_6) {
	target_6.getTarget().hasName("rec_get_instant_flag_new")
	and target_6.getArgument(0).(VariableAccess).getTarget().getType().hasName("const rec_t *")
	and target_6.getEnclosingFunction() = func
}

from Function func, Parameter vindex_793, Variable vnon_default_fields_797, VariableAccess target_1, VariableAccess target_2, FunctionCall target_3, FunctionCall target_4, ExprStmt target_5, FunctionCall target_6
where
not func_0(vindex_793, vnon_default_fields_797, target_4, target_5)
and func_1(vindex_793, target_1)
and func_2(vnon_default_fields_797, target_2)
and func_3(vindex_793, vnon_default_fields_797, target_3)
and func_4(vindex_793, target_4)
and func_5(vnon_default_fields_797, target_6, target_5)
and func_6(func, target_6)
and vindex_793.getType().hasName("const dict_index_t *")
and vnon_default_fields_797.getType().hasName("uint16_t")
and vindex_793.getFunction() = func
and vnon_default_fields_797.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
