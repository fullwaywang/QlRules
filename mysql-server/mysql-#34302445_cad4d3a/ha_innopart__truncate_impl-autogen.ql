/**
 * @name mysql-server-cad4d3a6f15d0ec09f555b75cddbf0c10b898890-ha_innopart__truncate_impl
 * @id cpp/mysql-server/cad4d3a6f15d0ec09f555b75cddbf0c10b898890/hainnoparttruncateimpl
 * @description mysql-server-cad4d3a6f15d0ec09f555b75cddbf0c10b898890-storage/innobase/handler/ha_innopart.cc-ha_innopart__truncate_impl mysql-#34302445
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verror_2982, VariableAccess target_3, ReturnStmt target_4, ReturnStmt target_5) {
exists(IfStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(AssignExpr obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getLValue().(VariableAccess).getTarget()=verror_2982
				and obj_2.getRValue().(Literal).getValue()="168"
			)
		)
	)
	and exists(BlockStmt obj_3 | obj_3=target_0.getParent() |
		exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
			obj_4.getThen().(BlockStmt).getStmt(1)=target_0
			and obj_4.getCondition()=target_3
		)
	)
	and target_0.getCondition().(EqualityOperation).getLeftOperand() instanceof FunctionCall
	and target_4.getExpr().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
	and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation())
)
}

/*predicate func_1(Variable verror_2982, ReturnStmt target_4, ReturnStmt target_5) {
exists(AssignExpr target_1 |
	target_1.getLValue().(VariableAccess).getTarget()=verror_2982
	and target_1.getRValue().(Literal).getValue()="168"
	and target_4.getExpr().(VariableAccess).getLocation().isBefore(target_1.getLValue().(VariableAccess).getLocation())
	and target_1.getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation())
)
}

*/
predicate func_2(Parameter vtable_def_2968, FunctionCall target_2) {
	target_2.getTarget().hasName("dd_clear_instant_table")
	and target_2.getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtable_def_2968
	and target_2.getArgument(1).(Literal).getValue()="1"
}

predicate func_3(Variable vis_instant_2986, VariableAccess target_3) {
	target_3.getTarget()=vis_instant_2986
}

predicate func_4(Variable verror_2982, EqualityOperation target_6, ReturnStmt target_4) {
	target_4.getExpr().(VariableAccess).getTarget()=verror_2982
	and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Variable verror_2982, ReturnStmt target_5) {
	target_5.getExpr().(VariableAccess).getTarget()=verror_2982
}

predicate func_6(Variable verror_2982, BlockStmt target_7, EqualityOperation target_6) {
	target_6.getLeftOperand().(VariableAccess).getTarget()=verror_2982
	and target_6.getRightOperand().(Literal).getValue()="0"
	and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(Variable verror_2982, EqualityOperation target_6, BlockStmt target_7) {
	target_7.getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getTarget()=verror_2982
	and target_7.getParent().(IfStmt).getCondition()=target_6
}

from Function func, Parameter vtable_def_2968, Variable verror_2982, Variable vis_instant_2986, FunctionCall target_2, VariableAccess target_3, ReturnStmt target_4, ReturnStmt target_5, EqualityOperation target_6, BlockStmt target_7
where
not func_0(verror_2982, target_3, target_4, target_5)
and func_2(vtable_def_2968, target_2)
and func_3(vis_instant_2986, target_3)
and func_4(verror_2982, target_6, target_4)
and func_5(verror_2982, target_5)
and func_6(verror_2982, target_7, target_6)
and func_7(verror_2982, target_6, target_7)
and vtable_def_2968.getType().hasName("Table *")
and verror_2982.getType().hasName("int")
and vis_instant_2986.getType().hasName("const bool")
and vtable_def_2968.getFunction() = func
and verror_2982.(LocalVariable).getFunction() = func
and vis_instant_2986.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
