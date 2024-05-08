/**
 * @name mysql-server-cad4d3a6f15d0ec09f555b75cddbf0c10b898890-ha_innobase__truncate_impl
 * @id cpp/mysql-server/cad4d3a6f15d0ec09f555b75cddbf0c10b898890/hainnobasetruncateimpl
 * @description mysql-server-cad4d3a6f15d0ec09f555b75cddbf0c10b898890-storage/innobase/handler/ha_innodb.cc-ha_innobase__truncate_impl mysql-#34302445
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verror_15235, VariableAccess target_3, EqualityOperation target_4, ReturnStmt target_5) {
exists(IfStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getThen() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getStmt(0) |
			exists(AssignExpr obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getLValue().(VariableAccess).getTarget()=verror_15235
				and obj_2.getRValue().(Literal).getValue()="168"
			)
		)
	)
	and exists(BlockStmt obj_3 | obj_3=target_0.getParent() |
		exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
			obj_4.getThen().(BlockStmt).getStmt(0)=target_0
			and obj_4.getCondition()=target_3
		)
	)
	and target_0.getCondition().(EqualityOperation).getLeftOperand() instanceof FunctionCall
	and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
	and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation())
)
}

/*predicate func_1(Variable verror_15235, EqualityOperation target_4, ReturnStmt target_5) {
exists(AssignExpr target_1 |
	target_1.getLValue().(VariableAccess).getTarget()=verror_15235
	and target_1.getRValue().(Literal).getValue()="168"
	and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getLValue().(VariableAccess).getLocation())
	and target_1.getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation())
)
}

*/
predicate func_2(Parameter vtable_def_15216, FunctionCall target_2) {
	target_2.getTarget().hasName("dd_clear_instant_table")
	and target_2.getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtable_def_15216
	and target_2.getArgument(1).(Literal).getValue()="1"
}

predicate func_3(Variable vis_instant_15236, VariableAccess target_3) {
	target_3.getTarget()=vis_instant_15236
}

predicate func_4(Variable verror_15235, EqualityOperation target_4) {
	target_4.getLeftOperand().(VariableAccess).getTarget()=verror_15235
	and target_4.getRightOperand().(Literal).getValue()="0"
}

predicate func_5(Variable verror_15235, Function func, ReturnStmt target_5) {
	target_5.getExpr().(VariableAccess).getTarget()=verror_15235
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

from Function func, Parameter vtable_def_15216, Variable verror_15235, Variable vis_instant_15236, FunctionCall target_2, VariableAccess target_3, EqualityOperation target_4, ReturnStmt target_5
where
not func_0(verror_15235, target_3, target_4, target_5)
and func_2(vtable_def_15216, target_2)
and func_3(vis_instant_15236, target_3)
and func_4(verror_15235, target_4)
and func_5(verror_15235, func, target_5)
and vtable_def_15216.getType().hasName("Table *")
and verror_15235.getType().hasName("int")
and vis_instant_15236.getType().hasName("const bool")
and vtable_def_15216.getFunction() = func
and verror_15235.(LocalVariable).getFunction() = func
and vis_instant_15236.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
