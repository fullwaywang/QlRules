/**
 * @name mysql-server-1052369eeda49c4af0286efecdf2cb1935b8627f-fil_tablespace_redo_extend
 * @id cpp/mysql-server/1052369eeda49c4af0286efecdf2cb1935b8627f/filtablespaceredoextend
 * @description mysql-server-1052369eeda49c4af0286efecdf2cb1935b8627f-storage/innobase/fil/fil0fil.cc-fil_tablespace_redo_extend mysql-#33002492
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_10797, Variable vphy_page_size_10803, Variable vend_fsize_10867, ExprStmt target_6, FunctionCall target_7) {
exists(AssignExpr target_0 |
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getLValue() |
		obj_0.getTarget().getName()="size"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vfile_10797
	)
	and exists(DivExpr obj_1 | obj_1=target_0.getRValue() |
		obj_1.getLeftOperand().(VariableAccess).getTarget()=vend_fsize_10867
		and obj_1.getRightOperand().(VariableAccess).getTarget()=vphy_page_size_10803
	)
	and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_7.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getRValue().(DivExpr).getRightOperand().(VariableAccess).getLocation())
)
}

predicate func_1(Variable vfile_10797, Variable vpages_added_10869, PointerFieldAccess target_1) {
	exists(AssignAddExpr obj_0 | obj_0=target_1.getParent() |
		obj_0.getLValue() = target_1
		and obj_0.getRValue().(VariableAccess).getTarget()=vpages_added_10869
	)
	and target_1.getTarget().getName()="size"
	and target_1.getQualifier().(VariableAccess).getTarget()=vfile_10797
}

predicate func_2(Variable vend_fsize_10867, VariableAccess target_2) {
	target_2.getTarget()=vend_fsize_10867
}

predicate func_3(Function func, DeclStmt target_3) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vinitial_fsize_10809, Variable vend_fsize_10867, SubExpr target_4) {
	target_4.getLeftOperand().(VariableAccess).getTarget()=vend_fsize_10867
	and target_4.getRightOperand().(VariableAccess).getTarget()=vinitial_fsize_10809
}

predicate func_5(Variable vfile_10797, Variable vpages_added_10869, AssignAddExpr target_5) {
	exists(PointerFieldAccess obj_0 | obj_0=target_5.getLValue() |
		obj_0.getTarget().getName()="size"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vfile_10797
	)
	and target_5.getRValue().(VariableAccess).getTarget()=vpages_added_10869
}

predicate func_6(Variable vfile_10797, ExprStmt target_6) {
	exists(AssignExpr obj_0 | obj_0=target_6.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="size"
			and obj_1.getQualifier().(VariableAccess).getTarget().getType().hasName("fil_space_t *")
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().getName()="size"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vfile_10797
		)
	)
}

predicate func_7(Variable vfile_10797, Variable vphy_page_size_10803, Variable vinitial_fsize_10809, FunctionCall target_7) {
	target_7.getTarget().hasName("fil_write_zeros")
	and target_7.getArgument(0).(VariableAccess).getTarget()=vfile_10797
	and target_7.getArgument(1).(VariableAccess).getTarget()=vphy_page_size_10803
	and target_7.getArgument(2).(VariableAccess).getTarget()=vinitial_fsize_10809
	and target_7.getArgument(3).(VariableAccess).getTarget().getType().hasName("os_offset_t")
	and target_7.getArgument(4).(Literal).getValue()="0"
}

from Function func, Variable vfile_10797, Variable vphy_page_size_10803, Variable vinitial_fsize_10809, Variable vend_fsize_10867, Variable vpages_added_10869, PointerFieldAccess target_1, VariableAccess target_2, DeclStmt target_3, SubExpr target_4, AssignAddExpr target_5, ExprStmt target_6, FunctionCall target_7
where
not func_0(vfile_10797, vphy_page_size_10803, vend_fsize_10867, target_6, target_7)
and func_1(vfile_10797, vpages_added_10869, target_1)
and func_2(vend_fsize_10867, target_2)
and func_3(func, target_3)
and func_4(vinitial_fsize_10809, vend_fsize_10867, target_4)
and func_5(vfile_10797, vpages_added_10869, target_5)
and func_6(vfile_10797, target_6)
and func_7(vfile_10797, vphy_page_size_10803, vinitial_fsize_10809, target_7)
and vfile_10797.getType().hasName("fil_node_t *")
and vphy_page_size_10803.getType().hasName("size_t")
and vinitial_fsize_10809.getType().hasName("os_offset_t")
and vend_fsize_10867.getType().hasName("os_offset_t")
and vpages_added_10869.getType().hasName("page_no_t")
and vfile_10797.(LocalVariable).getFunction() = func
and vphy_page_size_10803.(LocalVariable).getFunction() = func
and vinitial_fsize_10809.(LocalVariable).getFunction() = func
and vend_fsize_10867.(LocalVariable).getFunction() = func
and vpages_added_10869.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
